"""Security analysis engine.

This module is a *pure rule processor*. It receives already-parsed,
already-validated IAM data plus an :class:`AnalyzerConfig` describing the
environment context, and emits :class:`Finding` objects. It knows nothing
about files, CLIs, or report formats.

Design intent
-------------
The engine does not "grep for asterisks". For every rule family it asks a
contextual question:

* **A. PCI crown jewels** – does this statement actually reach a
  production payment secret / KMS key, or only a dev resource? Is there a
  control (permission boundary, network condition) that caps it?
* **B. Trust** – can an unintended principal assume this role, and is that
  trust fenced by a condition?
* **D. Escalation** – does the role hold a *combination* of permissions
  that lets it rewrite the IAM graph, regardless of how scoped each line
  looks in isolation?

Mitigations (**C**) are not a separate pass; they are applied inline so a
finding's final severity always reflects the real, post-control risk.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any, Iterable

from .config import AnalyzerConfig, SensitiveResource
from .models import (
    Finding,
    FindingType,
    PolicyStatement,
    RemediationCampaign,
    Severity,
)

# Minimum number of distinct CDE-touching statements before we bother
# flagging a missing-boundary gap. Roles with a single, fully-scoped
# statement (e.g. one specific secret ARN) still get this finding because
# the absence of a cap matters even for narrow access in a PCI context.
_BOUNDARY_GAP_MIN_STATEMENTS = 1

# A finding type + root cause must affect at least this many distinct roles
# before it is consolidated into a campaign instead of listed per-role.
CAMPAIGN_MIN_ROLES = 2

# Actions that mutate sensitive data (vs. merely read it). Used to push a
# crown-jewel finding from HIGH to CRITICAL.
_WRITE_ACTION_HINTS = (
    "put",
    "update",
    "delete",
    "create",
    "encrypt",
    "reencrypt",
    "generatedatakey",
)

# Companion actions that, paired with iam:PassRole on broad resources,
# constitute a *direct* IAM-graph rewrite (full takeover) rather than a
# softer lateral move. Drives CRITICAL vs HIGH on escalation findings.
_DIRECT_IAM_MUTATIONS = {
    "iam:createrole",
    "iam:attachrolepolicy",
    "iam:putrolepolicy",
    "iam:createpolicyversion",
    "iam:updateassumerolepolicy",
}


# --------------------------------------------------------------------------- #
# Wildcard matching helpers (IAM semantics: '*' = any run, '?' = one char)
# --------------------------------------------------------------------------- #
def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate an IAM-style glob into an anchored regex.

    Only ``*`` and ``?`` are special in IAM; every other character is a
    literal, so we escape the rest. Matching is case-insensitive, which is
    correct for action names and a safe over-approximation for ARNs.
    """
    out = ["^"]
    for ch in pattern:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    out.append("$")
    return re.compile("".join(out), re.IGNORECASE)


def _matches(pattern: str, value: str) -> bool:
    """True if ``value`` matches the glob ``pattern``."""
    return _glob_to_regex(pattern).fullmatch(value) is not None


def _patterns_overlap(a: str, b: str) -> bool:
    """True if two globs could match at least one common string.

    Policy ``Resource`` entries and our sensitive-resource definitions are
    *both* patterns, so a plain match in one direction misses cases like
    ``prod/*`` (statement) vs ``prod/providers/*`` (sensitive). We probe in
    both directions: substitute each pattern's wildcards with a sentinel to
    get a concrete witness string, then test it against the other glob.
    """
    if a == "*" or b == "*":
        return True
    sentinel = "\x00WILDCARD\x00"
    witness_a = a.replace("*", sentinel).replace("?", sentinel)
    witness_b = b.replace("*", sentinel).replace("?", sentinel)
    return _matches(a, witness_b) or _matches(b, witness_a)


def _action_in(action: str, candidates: Iterable[str]) -> bool:
    """True if a (possibly wildcarded) statement action covers any of the
    candidate concrete actions, or vice versa. Handles ``*`` and
    ``secretsmanager:*`` etc."""
    for cand in candidates:
        if _patterns_overlap(action, cand):
            return True
    return False


# --------------------------------------------------------------------------- #
# Statement helpers
# --------------------------------------------------------------------------- #
def _statement_fingerprint(stmt: PolicyStatement) -> str:
    """Stable short hash of a statement's *permission shape*.

    Order-insensitive over actions/resources so two byte-identical lax
    declarations (even copy-pasted into differently named inline policies)
    collapse to the same fingerprint and can be consolidated into one
    campaign.
    """
    payload = "|".join(
        [
            stmt.effect.lower(),
            ",".join(sorted(a.lower() for a in stmt.actions)),
            ",".join(sorted(r.lower() for r in stmt.resources)),
        ]
    )
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]


def _is_write_action(action: str) -> bool:
    low = action.lower()
    if low == "*" or low.endswith(":*"):
        return True
    verb = low.split(":", 1)[-1]
    return any(verb.startswith(h) for h in _WRITE_ACTION_HINTS)


def _statement_has_mitigating_condition(
    stmt: PolicyStatement, config: AnalyzerConfig
) -> list[str]:
    """Return the names of any recognized guardrail condition keys present
    on the statement with a non-empty value."""
    found: list[str] = []
    for _operator, kv in stmt.condition.items():
        if not isinstance(kv, dict):
            continue
        for key, value in kv.items():
            if key in config.mitigating_condition_keys and value not in (None, "", [], {}):
                found.append(key)
    return found


def _statement_touches(
    stmt: PolicyStatement, sensitive: SensitiveResource
) -> bool:
    for res in stmt.resources:
        for pat in sensitive.arn_patterns:
            if _patterns_overlap(res, pat):
                return True
    return False


def _resources_only_nonprod(
    stmt: PolicyStatement, config: AnalyzerConfig
) -> bool:
    """True if *every* resource on the statement is a recognized non-prod
    pattern (and the statement isn't a blanket ``*``)."""
    if not stmt.resources or "*" in stmt.resources:
        return False
    for res in stmt.resources:
        if not any(_matches(np, res) or _matches(res, np)
                   for np in config.non_production_patterns):
            return False
    return True


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #
class SecurityEngine:
    """Evaluates roles against the configured payment-environment context."""

    def __init__(self, config: AnalyzerConfig | None = None) -> None:
        self.config = config or AnalyzerConfig()

    # -- public API ------------------------------------------------------ #
    def analyze(
        self,
        roles: list[dict[str, Any]],
        managed_policies: dict[str, dict[str, Any]] | None = None,
    ) -> list[Finding]:
        """Analyze every role and return a flat list of findings.

        Parameters
        ----------
        roles:
            Entries shaped like ``get-account-authorization-details``
            ``RoleDetailList`` items.
        managed_policies:
            Map of managed-policy ARN -> ``{"PolicyName", "document"}`` used
            to resolve attached managed policies and permission boundaries.
        """
        managed_policies = managed_policies or {}
        findings: list[Finding] = []
        for role in roles:
            statements = self._effective_statements(role, managed_policies)
            boundary_arn = self._boundary_arn(role)
            boundary_caps = self._boundary_caps_actions(boundary_arn, managed_policies)

            findings.extend(
                self._check_pci_access(role, statements, boundary_arn, boundary_caps)
            )
            findings.extend(self._check_trust_policy(role))
            findings.extend(
                self._check_privilege_escalation(role, statements, boundary_arn)
            )
            findings.extend(
                self._check_missing_boundary(role, statements, boundary_arn)
            )
        # Highest severity first, then by role for stable output.
        findings.sort(key=lambda f: (-int(f.severity), f.role_name))
        return findings

    # -- statement resolution ------------------------------------------- #
    def _effective_statements(
        self, role: dict[str, Any], managed_policies: dict[str, dict[str, Any]]
    ) -> list[PolicyStatement]:
        """Flatten inline + attached-managed policies into normalized,
        Allow-only statements, preserving provenance for campaign grouping."""
        result: list[PolicyStatement] = []

        for inline in role.get("RolePolicyList", []) or []:
            doc = inline.get("PolicyDocument", {})
            result.extend(
                self._normalize(doc, "inline", inline.get("PolicyName", ""), None)
            )

        for attached in role.get("AttachedManagedPolicies", []) or []:
            arn = attached.get("PolicyArn")
            name = attached.get("PolicyName", "")
            managed = managed_policies.get(arn)
            if not managed:
                continue
            result.extend(
                self._normalize(managed.get("document", {}), "managed", name, arn)
            )

        return [s for s in result if s.is_allow]

    @staticmethod
    def _normalize(
        document: dict[str, Any],
        source_type: str,
        source_name: str,
        source_arn: str | None,
    ) -> list[PolicyStatement]:
        raw = document.get("Statement", [])
        if isinstance(raw, dict):
            raw = [raw]
        out: list[PolicyStatement] = []
        for s in raw:
            if not isinstance(s, dict):
                continue
            actions = s.get("Action", s.get("NotAction", []))
            resources = s.get("Resource", s.get("NotResource", []))
            out.append(
                PolicyStatement(
                    effect=s.get("Effect", "Allow"),
                    actions=[actions] if isinstance(actions, str) else list(actions),
                    resources=[resources] if isinstance(resources, str) else list(resources),
                    condition=s.get("Condition", {}) or {},
                    source_type=source_type,
                    source_name=source_name,
                    source_arn=source_arn,
                )
            )
        return out

    @staticmethod
    def _boundary_arn(role: dict[str, Any]) -> str | None:
        pb = role.get("PermissionsBoundary")
        if isinstance(pb, dict):
            return pb.get("PermissionsBoundaryArn")
        return None

    def _boundary_caps_actions(
        self,
        boundary_arn: str | None,
        managed_policies: dict[str, dict[str, Any]],
    ) -> bool:
        """Heuristic: does the boundary *meaningfully* restrict the role?

        If we can resolve the boundary document and it does NOT grant broad
        access (no ``*`` action and no sensitive-service wildcard), we treat
        it as a hard cap that strongly downgrades findings. If the boundary
        is unresolved we still credit its presence, but only by one step.
        """
        if not boundary_arn:
            return False
        managed = managed_policies.get(boundary_arn)
        if not managed:
            return False  # present but opaque -> caller credits 1 step
        for stmt in self._normalize(managed.get("document", {}), "managed", "", boundary_arn):
            if not stmt.is_allow:
                continue
            for action in stmt.actions:
                if action == "*" or action.endswith(":*"):
                    return False  # boundary itself is permissive -> no real cap
        return True

    # -- A. PCI crown-jewel access -------------------------------------- #
    def _check_pci_access(
        self,
        role: dict[str, Any],
        statements: list[PolicyStatement],
        boundary_arn: str | None,
        boundary_caps: bool,
    ) -> list[Finding]:
        findings: list[Finding] = []
        role_name = role["RoleName"]
        role_arn = role["Arn"]

        for stmt in statements:
            # An action touches a crown jewel if it matches a sensitive action
            # pattern (this already covers same-service wildcards like
            # "secretsmanager:*" via bidirectional glob overlap) or is the
            # blanket all-services "*". A service-scoped wildcard for an
            # unrelated service (e.g. "backup:*") deliberately does NOT match.
            touches_sensitive = any(
                _action_in(a, self.config.sensitive_actions) or a == "*"
                for a in stmt.actions
            )
            if not touches_sensitive:
                continue

            matched = [
                sr for sr in self.config.sensitive_resources
                if _statement_touches(stmt, sr)
            ]

            if matched:
                has_write = any(_is_write_action(a) for a in stmt.actions)
                wildcard_action = any(a == "*" or a.endswith(":*") for a in stmt.actions)
                base = Severity.CRITICAL if (has_write or wildcard_action) else Severity.HIGH

                severity, mitigations = self._apply_mitigations(
                    base, stmt, boundary_arn, boundary_caps
                )
                findings.append(
                    self._build_pci_finding(
                        role_name, role_arn, stmt, matched, base, severity, mitigations
                    )
                )
            elif _resources_only_nonprod(stmt, self.config):
                # Looks scary (wildcard on secrets/KMS) but is fenced to
                # dev/staging only -> deliberately downgraded to noise.
                findings.append(
                    Finding(
                        role_name=role_name,
                        role_arn=role_arn,
                        finding_type=FindingType.PCI_SENSITIVE_ACCESS,
                        title="Broad secret/KMS access scoped to non-production",
                        severity=Severity.INFORMATIONAL,
                        base_severity=Severity.LOW,
                        blast_radius=(
                            "Wildcard access to secrets/KMS, but every resource is a "
                            "dev/staging/sandbox prefix. No cardholder data is reachable; "
                            "outside the CDE and out of PCI DSS scope."
                        ),
                        remediation=(
                            "No urgent action. Optionally tighten the resource scope to "
                            "the specific non-prod ARNs to keep blast radius minimal."
                        ),
                        mitigations=["resource_scope:non_production_only"],
                        evidence={"actions": stmt.actions, "resources": stmt.resources,
                                  "source": stmt.source_name},
                        shared_policy_arn=stmt.source_arn,
                        shared_policy_name=stmt.source_name or None,
                        policy_fingerprint=_statement_fingerprint(stmt),
                    )
                )
        return findings

    def _apply_mitigations(
        self,
        base: Severity,
        stmt: PolicyStatement,
        boundary_arn: str | None,
        boundary_caps: bool,
    ) -> tuple[Severity, list[str]]:
        severity = base
        mitigations: list[str] = []

        cond_keys = _statement_has_mitigating_condition(stmt, self.config)
        if cond_keys:
            severity = severity.downgraded(1)
            mitigations.append(f"condition_keys:{','.join(cond_keys)}")

        if boundary_arn:
            if boundary_caps:
                severity = severity.downgraded(2)
                mitigations.append(f"permission_boundary_caps:{boundary_arn}")
            else:
                severity = severity.downgraded(1)
                mitigations.append(f"permission_boundary_present:{boundary_arn}")

        return severity, mitigations

    def _build_pci_finding(
        self,
        role_name: str,
        role_arn: str,
        stmt: PolicyStatement,
        matched: list[SensitiveResource],
        base: Severity,
        severity: Severity,
        mitigations: list[str],
    ) -> Finding:
        asset_names = ", ".join(sr.name for sr in matched)
        blast = " ".join(sr.blast_radius for sr in matched)

        # Build the least-privilege resource list. KMS *alias* ARNs cannot be
        # used as wildcards in identity policies for cryptographic actions —
        # IAM matches those against the key ARN (Key UUID), not the alias
        # string. So any KMS alias pattern is rewritten to a key-ARN form and
        # we flag that a clarifying note must be appended.
        scoped_resources: list[str] = []
        kms_alias_present = False
        for sr in matched:
            pat = sr.arn_patterns[0]
            if ":kms:" in pat and ":alias/" in pat:
                kms_alias_present = True
                if "arn:aws:kms:*:*:key/*" not in scoped_resources:
                    scoped_resources.append("arn:aws:kms:*:*:key/*")
            elif pat not in scoped_resources:
                scoped_resources.append(pat)

        remediation = (
            "Replace the wildcard/broad statement with a least-privilege block that "
            "(1) names only the exact secret/key ARNs the service needs, (2) drops "
            "write actions unless operationally required, and (3) adds an "
            "aws:SourceVpc (or aws:SourceVpce) guardrail so the credential is only "
            "usable from inside the production CDE network."
        )
        if kms_alias_present:
            remediation += (
                " Note: Replace the generic KMS key wildcard with your specific Key "
                "UUID ARNs during deployment, as IAM identity policies do not natively "
                "resolve wildcards on KMS alias strings for cryptographic operations."
            )

        remediation_policy = {
            "Effect": "Allow",
            "Action": [a for a in stmt.actions if a not in ("*",)] or ["secretsmanager:GetSecretValue"],
            "Resource": scoped_resources,
            "Condition": {
                "StringEquals": {"aws:SourceVpc": "vpc-REPLACE_WITH_PROD_VPC"}
            },
        }
        return Finding(
            role_name=role_name,
            role_arn=role_arn,
            finding_type=FindingType.PCI_SENSITIVE_ACCESS,
            title=f"Production payment asset access: {asset_names}",
            severity=severity,
            base_severity=base,
            blast_radius=blast,
            remediation=remediation,
            remediation_policy=remediation_policy,
            mitigations=mitigations,
            evidence={
                "actions": stmt.actions,
                "resources": stmt.resources,
                "source_type": stmt.source_type,
                "source_name": stmt.source_name,
            },
            shared_policy_arn=stmt.source_arn,
            shared_policy_name=stmt.source_name or None,
            policy_fingerprint=_statement_fingerprint(stmt),
        )

    # -- B. Insecure trust policies ------------------------------------- #
    def _check_trust_policy(self, role: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        role_name = role["RoleName"]
        role_arn = role["Arn"]
        trust = role.get("AssumeRolePolicyDocument", {}) or {}
        raw = trust.get("Statement", [])
        if isinstance(raw, dict):
            raw = [raw]

        for s in raw:
            if not isinstance(s, dict) or s.get("Effect", "Allow").lower() != "allow":
                continue
            principal = s.get("Principal", {})
            condition = s.get("Condition", {}) or {}
            has_condition = bool(condition)

            aws_principals = self._extract_aws_principals(principal)

            # B.1 Wildcard principal -> anyone on AWS can assume.
            if "*" in aws_principals:
                base = Severity.CRITICAL
                severity = base.downgraded(2) if has_condition else base
                findings.append(
                    self._build_trust_finding(
                        role_name, role_arn,
                        title="Trust policy allows assumption by ANY AWS principal",
                        base=base, severity=severity, has_condition=has_condition,
                        blast_radius=(
                            "Any AWS account on earth can assume this role and inherit all "
                            "of its permissions. In a payments context this is a direct path "
                            "into the CDE and an immediate PCI DSS Req. 7/8 failure."
                        ),
                        principal=principal, condition=condition,
                    )
                )
                continue

            # B.2 Cross-account ':root' trust to a non-owned account.
            for p in aws_principals:
                acct = self._root_account_id(p)
                if acct and acct not in self.config.trusted_account_ids:
                    base = Severity.HIGH
                    severity = base.downgraded(2) if has_condition else base
                    findings.append(
                        self._build_trust_finding(
                            role_name, role_arn,
                            title=f"Unconditioned cross-account root trust to {acct}",
                            base=base, severity=severity, has_condition=has_condition,
                            blast_radius=(
                                f"Every principal in external account {acct} can assume this "
                                "role. Without an sts:ExternalId / aws:PrincipalOrgID fence "
                                "this is exploitable via the confused-deputy pattern, exposing "
                                "whatever payment resources the role can reach."
                            ),
                            principal=principal, condition=condition,
                        )
                    )
        return findings

    @staticmethod
    def _extract_aws_principals(principal: Any) -> list[str]:
        if principal == "*":
            return ["*"]
        if not isinstance(principal, dict):
            return []
        aws = principal.get("AWS", [])
        if isinstance(aws, str):
            return [aws]
        return list(aws)

    @staticmethod
    def _root_account_id(arn: str) -> str | None:
        m = re.fullmatch(r"arn:aws:iam::(\d{12}):root", arn)
        return m.group(1) if m else None

    def _build_trust_finding(
        self, role_name: str, role_arn: str, *, title: str,
        base: Severity, severity: Severity, has_condition: bool,
        blast_radius: str, principal: Any, condition: dict[str, Any],
    ) -> Finding:
        mitigations = ["trust_condition_present"] if has_condition and severity < base else []
        remediation_policy = {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::TRUSTED_ACCOUNT:role/specific-caller-role"},
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "sts:ExternalId": "REPLACE_WITH_SHARED_SECRET",
                    "aws:PrincipalOrgID": "o-REPLACE_WITH_ORG_ID",
                }
            },
        }
        return Finding(
            role_name=role_name,
            role_arn=role_arn,
            finding_type=FindingType.INSECURE_TRUST_POLICY,
            title=title,
            severity=severity,
            base_severity=base,
            blast_radius=blast_radius,
            remediation=(
                "Replace the broad principal with the specific role ARN(s) that legitimately "
                "assume this role, and fence the trust with sts:ExternalId and/or "
                "aws:PrincipalOrgID so only your organization's known callers qualify."
            ),
            remediation_policy=remediation_policy,
            mitigations=mitigations,
            evidence={"principal": principal, "condition": condition},
        )

    # -- D. Privilege-escalation chains --------------------------------- #
    def _check_privilege_escalation(
        self,
        role: dict[str, Any],
        statements: list[PolicyStatement],
        boundary_arn: str | None,
    ) -> list[Finding]:
        role_name = role["RoleName"]
        role_arn = role["Arn"]

        # PassRole on broad resources is the pivot primitive.
        passrole_broad = any(
            _action_in(a, ["iam:PassRole"]) and self._is_broad(stmt.resources)
            for stmt in statements
            for a in stmt.actions
        )
        # All allow actions the role holds, lowercased for comparison.
        all_actions = {a.lower() for stmt in statements for a in stmt.actions}

        companions_present = [
            c for c in self.config.escalation_companion_actions
            if any(_action_in(a, [c]) for a in all_actions)
        ]
        direct_mutation = bool(_DIRECT_IAM_MUTATIONS & {c.lower() for c in companions_present})

        # Secondary path: CreateRole + Attach/PutRolePolicy is escalation even
        # without an explicit PassRole line (mint an admin role, then use it).
        create_attach = (
            any(_action_in(a, ["iam:CreateRole"]) for a in all_actions)
            and any(_action_in(a, ["iam:AttachRolePolicy", "iam:PutRolePolicy"]) for a in all_actions)
        )

        if not ((passrole_broad and companions_present) or create_attach):
            return []

        base = Severity.CRITICAL if (direct_mutation or create_attach) else Severity.HIGH
        severity = base.downgraded(1) if boundary_arn else base
        mitigations = [f"permission_boundary_present:{boundary_arn}"] if boundary_arn else []

        chain = "iam:PassRole(*)" if passrole_broad else "iam:CreateRole"
        chain += " + " + ", ".join(companions_present or ["iam:AttachRolePolicy"])

        return [
            Finding(
                role_name=role_name,
                role_arn=role_arn,
                finding_type=FindingType.PRIVILEGE_ESCALATION,
                title=f"Privilege-escalation chain: {chain}",
                severity=severity,
                base_severity=base,
                blast_radius=(
                    "This permission combination lets the principal mint or rewrite an IAM "
                    "role with arbitrary policies and hand it to a compute/service principal. "
                    "That is a path to full account takeover — including the tokenization "
                    "vault and payments KMS keys — i.e. total CDE compromise and a "
                    "catastrophic PCI DSS failure, independent of how narrow any single "
                    "statement looks."
                ),
                remediation=(
                    "Break the chain: scope iam:PassRole to the exact service-role ARNs the "
                    "workload must pass (never '*') and add an iam:PassedToService condition; "
                    "remove iam:CreateRole / iam:AttachRolePolicy / iam:PutRolePolicy unless "
                    "this is a provisioning role, in which case gate it behind a permission "
                    "boundary that the created roles must inherit."
                ),
                remediation_policy={
                    "Effect": "Allow",
                    "Action": ["iam:PassRole"],
                    "Resource": [
                        "arn:aws:iam::ACCOUNT:role/service-role/specific-task-role"
                    ],
                    "Condition": {
                        "StringEquals": {
                            "iam:PassedToService": "ecs-tasks.amazonaws.com"
                        }
                    },
                },
                mitigations=mitigations,
                evidence={"chain": chain, "companions": companions_present},
            )
        ]

    @staticmethod
    def _is_broad(resources: list[str]) -> bool:
        return any(r == "*" or r.endswith(":*") or r.endswith("/*") for r in resources)

    # -- E. Missing permission boundary on PCI-scope roles -------------- #
    def _check_missing_boundary(
        self,
        role: dict[str, Any],
        statements: list[PolicyStatement],
        boundary_arn: str | None,
    ) -> list[Finding]:
        """Flag PCI-scope roles that have no permission boundary at all.

        A permission boundary is a PCI DSS defense-in-depth control (Req. 7):
        it caps the *maximum* effective permissions so that a future policy
        attachment — accidental or malicious — cannot silently expand beyond
        what the role was designed to do. Its absence is a control gap even
        when the current access statements look correctly scoped, because the
        gap only needs to matter once.

        This is intentionally a **separate** finding from rule A (PCI access).
        Rule A fires when the *current* access is too broad. Rule E fires when
        the *future-proofing control* is absent, even if the current access is
        perfectly scoped. Both can fire on the same role at different severities.
        """
        if boundary_arn:
            return []  # any boundary present — gap is closed

        # Collect only statements that both (a) carry a sensitive action (or the
        # all-services wildcard) AND (b) reach a PCI-sensitive resource. This
        # dual-gate prevents false positives from roles like observability-agent
        # that use Resource:"*" for CloudWatch/Logs but whose actions never
        # actually access Secrets Manager or KMS.
        pci_stmts = [
            stmt for stmt in statements
            if (
                any(
                    _action_in(a, self.config.sensitive_actions) or a == "*"
                    for a in stmt.actions
                )
                and any(
                    _statement_touches(stmt, sr) for sr in self.config.sensitive_resources
                )
            )
        ]
        if len(pci_stmts) < _BOUNDARY_GAP_MIN_STATEMENTS:
            return []

        # Derive a concrete sample policy for the boundary suggestion:
        # use the union of touched sensitive resource ARNs as the scope.
        touched_patterns: list[str] = []
        sample_actions: list[str] = []
        for stmt in pci_stmts:
            for sr in self.config.sensitive_resources:
                if _statement_touches(stmt, sr):
                    for pat in sr.arn_patterns:
                        if pat not in touched_patterns:
                            touched_patterns.append(pat)
            for a in stmt.actions:
                if a not in ("*",) and a not in sample_actions:
                    sample_actions.append(a)

        # Replace alias ARNs with key/* form (same KMS correction as rule A).
        safe_resources = [
            "arn:aws:kms:*:*:key/*" if (":kms:" in p and ":alias/" in p) else p
            for p in touched_patterns
        ]

        boundary_policy = {
            "Effect": "Allow",
            "Action": sample_actions[:6] or ["secretsmanager:GetSecretValue"],
            "Resource": safe_resources[:4],
        }

        return [
            Finding(
                role_name=role["RoleName"],
                role_arn=role["Arn"],
                finding_type=FindingType.MISSING_PERMISSION_BOUNDARY,
                title="PCI-scope role has no permission boundary",
                severity=Severity.MEDIUM,
                base_severity=Severity.MEDIUM,
                blast_radius=(
                    "Without a permission boundary, this role's maximum effective "
                    "permissions are uncapped. Any future inline or managed policy "
                    "attachment — deliberate or accidental — becomes effective "
                    "immediately. For a role that already touches cardholder data "
                    "(Secrets Manager or KMS), this means a single misconfigured "
                    "attachment could silently promote the role to full-CDE access, "
                    "violating PCI DSS Req. 7 (least-privilege enforcement) without "
                    "any access-control review catching it."
                ),
                remediation=(
                    "Attach a permission boundary that allows only the service-level "
                    "API calls this role legitimately needs. Even a coarse boundary "
                    "(read-specific secrets + KMS decrypt) is significantly safer "
                    "than none. Use 'aws iam put-role-permissions-boundary' or the "
                    "Terraform block below. The boundary should be maintained by a "
                    "separate team or automation pipeline from the role's policies."
                ),
                remediation_policy=boundary_policy,
                evidence={
                    "pci_statements_count": len(pci_stmts),
                    "sample_actions": sample_actions[:6],
                    "sample_resources": [s.resources for s in pci_stmts[:2]],
                },
            )
        ]


# --------------------------------------------------------------------------- #
# Remediation campaigns (stretch goal)
# --------------------------------------------------------------------------- #
def _campaign_key(finding: Finding) -> tuple[FindingType, str, str] | None:
    """Compute the shared-root-cause key for a finding, or ``None`` if it has
    no consolidatable origin.

    Two roles share a root cause when they attach the **same managed policy**
    (definitive, keyed by ARN) or carry a **byte-identical permission
    declaration** (keyed by fingerprint). The fingerprint case subsumes the
    "same policy name copy-pasted around" scenario — identical content is the
    real signal, regardless of whether the inline policy names happen to
    match. The :class:`FindingType` is part of the key so unrelated rule
    families are never merged.
    """
    if finding.shared_policy_arn:
        return (finding.finding_type, "arn", finding.shared_policy_arn)
    if finding.policy_fingerprint:
        return (finding.finding_type, "fingerprint", finding.policy_fingerprint)
    return None


def consolidate_campaigns(
    findings: list[Finding],
) -> tuple[list[RemediationCampaign], list[Finding]]:
    """Group findings that share a single root cause into remediation campaigns.

    Returns ``(campaigns, standalone_findings)``:

    * **campaigns**  – one per (finding type + shared root cause) that affects
      >= ``CAMPAIGN_MIN_ROLES`` distinct roles. Fixing the central policy
      resolves every listed role at once.
    * **standalone** – findings with no shared origin, or whose group is a
      single role, rendered individually.

    This lives in the engine (not the reporter) so the consolidation is part
    of the analysis result and is reused identically by every output format.
    """
    grouped: dict[tuple[FindingType, str, str], list[Finding]] = defaultdict(list)
    standalone: list[Finding] = []

    for f in findings:
        key = _campaign_key(f)
        if key is None:
            standalone.append(f)
        else:
            grouped[key].append(f)

    campaigns: list[RemediationCampaign] = []
    for key, group in grouped.items():
        distinct_roles = sorted({f.role_name for f in group})
        if len(distinct_roles) < CAMPAIGN_MIN_ROLES:
            # Not actually shared across roles -> emit individually.
            standalone.extend(group)
            continue

        ftype, kind, raw_id = key
        top = max(group, key=lambda f: int(f.severity))

        if kind == "arn":
            kind_label = "shared managed policy"
            identifier = raw_id
        else:
            # Identical inline declarations. Prefer a shared human-readable
            # policy name as the identifier when every member agrees on one;
            # otherwise fall back to the fingerprint hash.
            names = {f.shared_policy_name for f in group if f.shared_policy_name}
            if len(names) == 1:
                kind_label = "shared policy name"
                identifier = next(iter(names))
            else:
                kind_label = "identical permission declaration"
                identifier = f"fingerprint:{raw_id}"

        campaigns.append(
            RemediationCampaign(
                campaign_id="",  # assigned after sorting for stable numbering
                title=top.title,
                description=(
                    f"{len(distinct_roles)} roles are exposed through the same "
                    f"{kind_label} (`{identifier}`). Remediating the central root cause "
                    f"once resolves all of them, instead of editing {len(distinct_roles)} "
                    "roles individually."
                ),
                finding_type=ftype,
                severity=top.severity,
                affected_roles=distinct_roles,
                remediation=(
                    f"Fix the {kind_label} `{identifier}` at the source. " + top.remediation
                ),
                policy_arn=identifier,
                remediation_policy=top.remediation_policy,
            )
        )

    # Deterministic ordering, then assign human-friendly sequential IDs.
    campaigns.sort(key=lambda c: (-int(c.severity), c.policy_arn))
    for i, c in enumerate(campaigns, 1):
        c.campaign_id = f"CAMP-{i:03d}"

    standalone.sort(key=lambda f: (-int(f.severity), f.role_name))
    return campaigns, standalone
