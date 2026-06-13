"""Ingestion and validation of AWS IAM exports.

Accepts the output of ``aws iam get-account-authorization-details`` (the
canonical, complete export). The parser's only job is to turn an untrusted
file on disk into the two clean structures the engine consumes:

* ``roles``            – the ``RoleDetailList`` entries, validated.
* ``managed_policies`` – a map of policy ARN -> {"PolicyName", "document"}
  where ``document`` is already resolved to the *default* version.

All malformed-input handling lives here so the engine can assume clean
data. Failures raise :class:`ParserError` with an actionable message.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class ParserError(Exception):
    """Raised when the input cannot be turned into analyzable data."""


@dataclass
class ParsedAccount:
    roles: list[dict[str, Any]] = field(default_factory=list)
    managed_policies: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Non-fatal issues (skipped roles, unresolved policies) surfaced to the
    # user so silent data loss never happens.
    warnings: list[str] = field(default_factory=list)


# Keys an entry must have to be analyzable as a role.
_REQUIRED_ROLE_KEYS = ("RoleName", "Arn")


def load_export(path: str | Path) -> ParsedAccount:
    """Read and validate an IAM export file.

    Raises
    ------
    ParserError
        If the file is missing, not valid JSON, or not a recognizable
        authorization-details document.
    """
    p = Path(path)
    if not p.is_file():
        raise ParserError(f"Input file not found: {p}")

    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ParserError(
            f"Input is not valid JSON ({exc.msg} at line {exc.lineno}, col {exc.colno})."
        ) from exc
    except OSError as exc:
        raise ParserError(f"Could not read input file: {exc}") from exc

    return parse_document(raw)


def parse_document(raw: Any) -> ParsedAccount:
    """Validate and normalize an already-parsed document.

    Separated from :func:`load_export` so it is unit-testable without disk
    I/O and reusable when the export arrives over a pipe/stdin.
    """
    if not isinstance(raw, dict):
        raise ParserError(
            "Top-level JSON must be an object (an IAM get-account-authorization-details "
            f"document); got {type(raw).__name__}."
        )

    role_list = raw.get("RoleDetailList")
    if role_list is None:
        raise ParserError(
            "Missing 'RoleDetailList'. This tool expects the output of "
            "'aws iam get-account-authorization-details'."
        )
    if not isinstance(role_list, list):
        raise ParserError("'RoleDetailList' must be a list.")

    account = ParsedAccount()
    account.managed_policies = _resolve_managed_policies(
        raw.get("Policies", []), account.warnings
    )

    for idx, role in enumerate(role_list):
        if not isinstance(role, dict):
            account.warnings.append(f"Skipped RoleDetailList[{idx}]: not an object.")
            continue
        missing = [k for k in _REQUIRED_ROLE_KEYS if not role.get(k)]
        if missing:
            account.warnings.append(
                f"Skipped RoleDetailList[{idx}]: missing required key(s) {missing}."
            )
            continue
        account.roles.append(_sanitize_role(role, account.warnings))

    if not account.roles:
        raise ParserError("No analyzable roles found in 'RoleDetailList'.")

    return account


def _resolve_managed_policies(
    policies: Any, warnings: list[str]
) -> dict[str, dict[str, Any]]:
    """Build {arn -> {PolicyName, document}} from the 'Policies' section,
    selecting each policy's default version document."""
    resolved: dict[str, dict[str, Any]] = {}
    if not isinstance(policies, list):
        warnings.append("'Policies' is not a list; managed policies left unresolved.")
        return resolved

    for idx, pol in enumerate(policies):
        if not isinstance(pol, dict):
            warnings.append(f"Skipped Policies[{idx}]: not an object.")
            continue
        arn = pol.get("Arn")
        if not arn:
            warnings.append(f"Skipped Policies[{idx}]: missing 'Arn'.")
            continue

        versions = pol.get("PolicyVersionList", [])
        document = _select_default_version(versions, pol.get("DefaultVersionId"))
        if document is None:
            warnings.append(
                f"Policy {arn}: no resolvable default version document; "
                "roles relying on it cannot be fully evaluated."
            )
            continue
        resolved[arn] = {
            "PolicyName": pol.get("PolicyName", ""),
            "document": document,
        }
    return resolved


def _select_default_version(
    versions: Any, default_id: str | None
) -> dict[str, Any] | None:
    if not isinstance(versions, list) or not versions:
        return None
    # Prefer the explicitly flagged default; fall back to DefaultVersionId
    # match; finally the first version present.
    for v in versions:
        if isinstance(v, dict) and v.get("IsDefaultVersion") and isinstance(v.get("Document"), dict):
            return v["Document"]
    if default_id:
        for v in versions:
            if isinstance(v, dict) and v.get("VersionId") == default_id and isinstance(v.get("Document"), dict):
                return v["Document"]
    first = versions[0]
    if isinstance(first, dict) and isinstance(first.get("Document"), dict):
        return first["Document"]
    return None


def _sanitize_role(role: dict[str, Any], warnings: list[str]) -> dict[str, Any]:
    """Defensively coerce the list-typed fields the engine iterates over so
    a single malformed role can't crash analysis."""
    for list_key in ("RolePolicyList", "AttachedManagedPolicies"):
        val = role.get(list_key)
        if val is not None and not isinstance(val, list):
            warnings.append(
                f"Role {role.get('RoleName')}: '{list_key}' is not a list; ignoring it."
            )
            role[list_key] = []
    trust = role.get("AssumeRolePolicyDocument")
    if trust is not None and not isinstance(trust, dict):
        warnings.append(
            f"Role {role.get('RoleName')}: malformed AssumeRolePolicyDocument; ignoring it."
        )
        role["AssumeRolePolicyDocument"] = {}
    return role
