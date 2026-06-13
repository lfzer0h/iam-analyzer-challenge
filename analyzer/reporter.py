"""Report generation: human-readable Markdown and structured JSON.

The reporter owns three concerns the engine deliberately stays out of:

1. **Remediation campaigns**: fold findings that share a root cause into one
   consolidated recommendation (see :func:`build_campaigns`).
2. **Presentation**: Markdown tables, severity badges, fenced code blocks.
3. **Terraform codegen**: translate each ``remediation_policy`` dict into a
   copy-paste–ready HCL block (``aws_iam_policy`` + attachments, or
   ``aws_iam_role`` for trust-policy corrections). The resulting string is
   stored as ``remediation_terraform`` in the JSON output and rendered as a
   fenced ``hcl`` block in the Markdown, directly below the JSON block.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .engine import consolidate_campaigns
from .models import Finding, FindingType, RemediationCampaign, Severity

# ---------------------------------------------------------------------------
# Severity display helpers
# ---------------------------------------------------------------------------
_SEVERITY_BADGE = {
    Severity.CRITICAL: "🔴 Critical",
    Severity.HIGH: "🟠 High",
    Severity.MEDIUM: "🟡 Medium",
    Severity.LOW: "🔵 Low",
    Severity.INFORMATIONAL: "⚪ Informational",
}

# ---------------------------------------------------------------------------
# HCL / Terraform generation
# ---------------------------------------------------------------------------

_IDENT_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
_HCL_UNIT = "  "  # 2-space indent per level (matches `terraform fmt`)


def _slug(text: str) -> str:
    """Sanitize arbitrary text into a valid Terraform resource name.

    Keeps only lower-case alphanumerics and underscores, collapses runs of
    non-alnum chars into a single underscore, and trims to 64 characters so
    the resulting ``aws_iam_policy`` ``name`` attribute stays under the 128-
    character AWS limit after the ``yuno-remediated-`` prefix.
    """
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:64]


def _hcl_key(k: str) -> str:
    """Return an HCL attribute key, quoting only when the name contains
    characters that are not valid bare identifiers (e.g. ``aws:SourceVpc``,
    ``sts:ExternalId``).
    """
    return k if _IDENT_RE.match(k) else f'"{k}"'


def _hcl_value(val: Any, level: int = 0) -> str:
    """Recursively serialize a Python value to an HCL *expression*.

    The ``level`` parameter controls indentation of the *content* inside
    delimiters — not the opening delimiter itself (which is always inline).
    This lets callers write:

        ``f"  policy = jsonencode({_hcl_value(doc, level=1)})"``

    and get:

        .. code-block:: hcl

            policy = jsonencode({
              Version   = "2012-10-17"
              Statement = [
                {
                  Effect = "Allow"
                  ...
                },
              ]
            })

    Rules:
    * **Dict** → ``{\\n  key = value\\n}``  (no trailing commas; newlines
      are sufficient attribute separators in HCL)
    * **List of strings** → inline ``["a", "b"]`` when the serialized form
      fits in 80 columns; multi-line otherwise
    * **List containing objects** → always multi-line with trailing commas
    * **String** → ``"quoted"``
    * **bool/None/number** → HCL literals
    """
    pad = _HCL_UNIT * level
    inner = _HCL_UNIT * (level + 1)

    if isinstance(val, dict):
        if not val:
            return "{}"
        parts = [
            f"{inner}{_hcl_key(k)} = {_hcl_value(v, level + 1)}"
            for k, v in val.items()
        ]
        return "{\n" + "\n".join(parts) + "\n" + pad + "}"

    if isinstance(val, list):
        if not val:
            return "[]"
        if all(isinstance(x, str) for x in val):
            inline = "[" + ", ".join(f'"{x}"' for x in val) + "]"
            if len(inline) < 80:
                return inline
        # Multi-line (objects, or long string lists).
        parts = [f"{inner}{_hcl_value(item, level + 1)}," for item in val]
        return "[\n" + "\n".join(parts) + "\n" + pad + "]"

    if isinstance(val, str):
        return f'"{val}"'
    if isinstance(val, bool):
        return "true" if val else "false"
    if val is None:
        return "null"
    return str(val)


def _render_finding_terraform(finding: Finding) -> str | None:
    """Generate a copy-paste–ready HCL block for a standalone finding.

    * **PCI / Escalation findings** → ``aws_iam_policy`` resource containing
      the least-privilege corrected statement, plus an
      ``aws_iam_role_policy_attachment`` to wire it to the affected role.
    * **Insecure trust-policy findings** → ``aws_iam_role`` resource that
      updates the role's ``assume_role_policy`` in place, guarded by a
      ``lifecycle`` block that prevents unintended attribute drift.
    * Findings with no ``remediation_policy`` → ``None`` (caller skips the
      block).
    """
    if finding.remediation_policy is None:
        return None

    res_slug = _slug(f"{finding.role_name}_{finding.finding_type.value}")
    role_slug = _slug(finding.role_name)

    if finding.finding_type == FindingType.MISSING_PERMISSION_BOUNDARY:
        role_slug = _slug(finding.role_name)
        boundary_slug = _slug(f"boundary_{finding.role_name}")
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [finding.remediation_policy],
        }
        return "\n".join([
            f"# Attaches a permissions boundary — caps maximum effective permissions.",
            f"# Step 1: import the existing role (run once):",
            f"#   terraform import aws_iam_role.{role_slug} {finding.role_name}",
            f"",
            f'resource "aws_iam_policy" "{boundary_slug}" {{',
            f'  name        = "yuno-boundary-{_slug(finding.role_name)}"',
            f'  description = "Permission boundary — IAM Contextual Risk Analyzer"',
            f"",
            f"  policy = jsonencode({_hcl_value(policy_doc, level=1)})",
            f"}}",
            f"",
            f'resource "aws_iam_role" "{role_slug}" {{',
            f'  name                 = "{finding.role_name}"',
            f"  permissions_boundary = aws_iam_policy.{boundary_slug}.arn",
            f"",
            f"  lifecycle {{",
            f"    ignore_changes = [assume_role_policy, inline_policy, description, path, tags]",
            f"  }}",
            f"}}",
        ])

    if finding.finding_type == FindingType.INSECURE_TRUST_POLICY:
        trust_doc = {
            "Version": "2012-10-17",
            "Statement": [finding.remediation_policy],
        }
        return "\n".join([
            f"# Note: Updates the trust policy of existing role '{finding.role_name}'.",
            f"# Bring it under Terraform management first:",
            f"#   terraform import aws_iam_role.{role_slug} {finding.role_name}",
            f"",
            f'resource "aws_iam_role" "{role_slug}" {{',
            f'  name = "{finding.role_name}"',
            f"",
            f"  assume_role_policy = jsonencode({_hcl_value(trust_doc, level=1)})",
            f"",
            f"  lifecycle {{",
            f"    ignore_changes = [description, path, tags]",
            f"  }}",
            f"}}",
        ])

    # PCI_SENSITIVE_ACCESS and PRIVILEGE_ESCALATION
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [finding.remediation_policy],
    }
    return "\n".join([
        f'resource "aws_iam_policy" "remediated_{res_slug}" {{',
        f'  name        = "yuno-remediated-{_slug(finding.role_name)}"',
        f'  description = "Least-privilege policy — IAM Contextual Risk Analyzer"',
        f"",
        f"  policy = jsonencode({_hcl_value(policy_doc, level=1)})",
        f"}}",
        f"",
        f'resource "aws_iam_role_policy_attachment" "remediated_{res_slug}" {{',
        f'  role       = "{finding.role_name}"  # replace with your tf resource reference',
        f"  policy_arn = aws_iam_policy.remediated_{res_slug}.arn",
        f"}}",
    ])


def _render_campaign_terraform(campaign: RemediationCampaign) -> str | None:
    """Generate HCL for a remediation campaign.

    Produces one ``aws_iam_policy`` resource (the corrected central policy)
    and one ``aws_iam_role_policy_attachment`` per affected role, so the
    entire campaign is fixed by a single ``terraform apply``.
    """
    if campaign.remediation_policy is None:
        return None

    camp_slug = _slug(campaign.campaign_id)
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [campaign.remediation_policy],
    }

    lines = [
        f"# {campaign.campaign_id} — root cause: {campaign.policy_arn}",
        f"# Fixes {len(campaign.affected_roles)} roles in one apply: "
        + ", ".join(campaign.affected_roles),
        f"",
        f'resource "aws_iam_policy" "remediated_{camp_slug}" {{',
        f'  name        = "yuno-remediated-{camp_slug}"',
        f'  description = "Least-privilege policy — IAM Contextual Risk Analyzer ({campaign.campaign_id})"',
        f"",
        f"  policy = jsonencode({_hcl_value(policy_doc, level=1)})",
        f"}}",
    ]

    for role_name in campaign.affected_roles:
        attach_slug = _slug(f"{campaign.campaign_id}_{role_name}")
        lines += [
            f"",
            f'resource "aws_iam_role_policy_attachment" "remediated_{attach_slug}" {{',
            f'  role       = "{role_name}"  # replace with your tf resource reference',
            f"  policy_arn = aws_iam_policy.remediated_{camp_slug}.arn",
            f"}}",
        ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_campaigns(
    findings: list[Finding],
) -> tuple[list[RemediationCampaign], list[Finding]]:
    """Split findings into (campaigns, standalone findings).

    Thin wrapper kept for backward-compatibility and test discoverability;
    the consolidation logic lives in the engine so every output format
    shares one source of truth.
    """
    return consolidate_campaigns(findings)


def write_reports(
    findings: list[Finding],
    output_dir: str | Path,
    warnings: list[str] | None = None,
) -> dict[str, Path]:
    """Write ``report.md`` and ``findings.json`` into ``output_dir``.

    Both files are derived from the same consolidation pass so their
    campaign lists and finding lists are always in sync.

    Returns ``{"markdown": Path, "json": Path}``.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    warnings = warnings or []

    campaigns, standalone = build_campaigns(findings)

    # Pre-compute Terraform strings once; reuse in both outputs.
    campaign_tf = {c.campaign_id: _render_campaign_terraform(c) for c in campaigns}
    finding_tf = {
        (f.role_name, f.finding_type): _render_finding_terraform(f)
        for f in standalone
    }

    # ---- JSON -------------------------------------------------------
    def _campaign_dict(c: RemediationCampaign) -> dict[str, Any]:
        d = c.to_dict()
        d["remediation_terraform"] = campaign_tf.get(c.campaign_id)
        return d

    def _finding_dict(f: Finding) -> dict[str, Any]:
        d = f.to_dict()
        d["remediation_terraform"] = finding_tf.get((f.role_name, f.finding_type))
        return d

    json_path = out / "findings.json"
    json_path.write_text(
        json.dumps(
            {
                "summary": _summary(findings),
                "remediation_campaigns": [_campaign_dict(c) for c in campaigns],
                "findings": [_finding_dict(f) for f in standalone],
                "warnings": warnings,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    # ---- Markdown ---------------------------------------------------
    md_path = out / "report.md"
    md_path.write_text(
        _render_markdown(
            findings, campaigns, standalone, warnings, campaign_tf, finding_tf
        ),
        encoding="utf-8",
    )

    return {"markdown": md_path, "json": json_path}


# ---------------------------------------------------------------------------
# Internal rendering helpers
# ---------------------------------------------------------------------------

def _summary(findings: list[Finding]) -> dict[str, Any]:
    counts = {s.label: 0 for s in reversed(Severity)}
    mitigated = 0
    for f in findings:
        counts[f.severity.label] += 1
        if f.was_mitigated:
            mitigated += 1
    return {
        "total_findings": len(findings),
        "by_severity": counts,
        "mitigated_findings": mitigated,
    }


def _md_json_block(lines: list[str], data: Any) -> None:
    lines.append("```json")
    lines.append(json.dumps(data, indent=2))
    lines.append("```")


def _md_hcl_block(lines: list[str], hcl: str | None) -> None:
    if not hcl:
        return
    lines.append("")
    lines.append("**Terraform (ready for PR):**")
    lines.append("")
    lines.append("```hcl")
    lines.append(hcl)
    lines.append("```")


def _render_markdown(
    findings: list[Finding],
    campaigns: list[RemediationCampaign],
    standalone: list[Finding],
    warnings: list[str],
    campaign_tf: dict[str, str | None],
    finding_tf: dict[tuple, str | None],
) -> str:
    s = _summary(findings)
    lines: list[str] = []

    lines.append("# IAM Contextual Risk Report")
    lines.append("")
    lines.append(
        "> Blast-radius–aware analysis of an AWS IAM export, scoped to a PCI DSS "
        "payment-processing environment. Severities are **post-mitigation**: a "
        "finding marked _mitigated_ had its base severity lowered because a real, "
        "verified control (permission boundary, network condition, scoped resource) "
        "caps the exposure."
    )
    lines.append("")

    # ---- Summary table -----------------------------------------------
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                Severity.LOW, Severity.INFORMATIONAL):
        lines.append(f"| {_SEVERITY_BADGE[sev]} | {s['by_severity'][sev.label]} |")
    lines.append(f"| **Total** | **{s['total_findings']}** |")
    lines.append("")
    lines.append(
        f"_{s['mitigated_findings']} finding(s) were downgraded by verified mitigations._"
    )
    lines.append("")

    # ---- Campaigns (directly below executive summary) ----------------
    if campaigns:
        lines.append("## 🎯 Campaigns of Remediation (Stretch Goals)")
        lines.append("")
        lines.append(
            "Multiple roles share the **same root cause** (a common managed policy, "
            "a reused policy name, or a byte-identical permission declaration). "
            "Fixing the central policy once resolves every listed role — do this "
            "before chasing the per-role findings below."
        )
        lines.append("")
        for c in campaigns:
            lines.append(f"### {c.campaign_id} — `{c.policy_arn}`")
            lines.append("")
            lines.append(f"- **Severity:** {_SEVERITY_BADGE[c.severity]}")
            lines.append(f"- **Finding type:** `{c.finding_type.value}`")
            lines.append(f"- **Description:** {c.description}")
            lines.append(
                f"- **Affected roles ({len(c.affected_roles)}):** "
                + ", ".join(f"`{r}`" for r in c.affected_roles)
            )
            lines.append(f"- **Remediation:** {c.remediation}")
            if c.remediation_policy:
                lines.append("")
                lines.append("**Least-privilege replacement:**")
                lines.append("")
                _md_json_block(lines, c.remediation_policy)
                _md_hcl_block(lines, campaign_tf.get(c.campaign_id))
            lines.append("")

    # ---- Standalone findings -----------------------------------------
    lines.append("## Findings")
    lines.append("")
    if not standalone:
        lines.append("_No standalone findings._")
        lines.append("")
    for i, f in enumerate(standalone, 1):
        lines.append(f"### {i}. `{f.role_name}` — {f.title}")
        lines.append("")
        sev_line = f"- **Severity:** {_SEVERITY_BADGE[f.severity]}"
        if f.was_mitigated:
            sev_line += f" _(base {f.base_severity.label}, mitigated)_"
        lines.append(sev_line)
        lines.append(f"- **Finding type:** `{f.finding_type.value}`")
        lines.append(f"- **Role ARN:** `{f.role_arn}`")
        if f.mitigations:
            lines.append(
                f"- **Mitigations applied:** "
                + ", ".join(f"`{m}`" for m in f.mitigations)
            )
        lines.append(f"- **Blast radius:** {f.blast_radius}")
        lines.append(f"- **Remediation:** {f.remediation}")
        if f.evidence:
            lines.append("")
            lines.append("<details><summary>Evidence</summary>")
            lines.append("")
            _md_json_block(lines, f.evidence)
            lines.append("</details>")
        if f.remediation_policy:
            lines.append("")
            lines.append("**Least-privilege replacement:**")
            lines.append("")
            _md_json_block(lines, f.remediation_policy)
            _md_hcl_block(lines, finding_tf.get((f.role_name, f.finding_type)))
        lines.append("")

    # ---- Parser warnings ---------------------------------------------
    if warnings:
        lines.append("## Parser Warnings")
        lines.append("")
        for w in warnings:
            lines.append(f"- {w}")
        lines.append("")

    return "\n".join(lines)
