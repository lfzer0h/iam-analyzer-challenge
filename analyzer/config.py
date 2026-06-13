"""Analysis configuration: the *context* the engine reasons against.

Everything that is specific to a given environment (which secret prefixes
are PCI-sensitive, which KMS aliases protect cardholder data, which
account IDs are trusted) lives here — never inside the engine logic. This
keeps the engine a pure rule processor and lets a different organization
re-target the tool by editing one file or passing a YAML override.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SensitiveResource:
    """A class of crown-jewel resource and what compromising it means."""

    name: str
    # ARN glob(s) that identify the resource in policy statements.
    arn_patterns: list[str]
    # Plain-language description of the PCI / business impact, reused
    # verbatim when building the Blast Radius narrative.
    blast_radius: str


@dataclass
class AnalyzerConfig:
    """Tunable context for one analysis run."""

    # --- A. PCI crown jewels --------------------------------------------
    sensitive_resources: list[SensitiveResource] = field(
        default_factory=lambda: [
            SensitiveResource(
                name="Provider credentials (Secrets Manager)",
                arn_patterns=[
                    "arn:aws:secretsmanager:*:*:secret:prod/providers/*",
                ],
                blast_radius=(
                    "Exposes live acquirer / PSP API credentials. An attacker could "
                    "initiate or reroute settlements on behalf of the gateway, "
                    "breaching PCI DSS Req. 3 (protection of stored credentials) and "
                    "Req. 7 (least privilege on cardholder-data systems)."
                ),
            ),
            SensitiveResource(
                name="Tokenization vault secrets (Secrets Manager)",
                arn_patterns=[
                    "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*",
                ],
                blast_radius=(
                    "Grants reach into the tokenization vault that maps tokens to PANs. "
                    "Compromise enables detokenization of cardholder data — a reportable "
                    "PCI DSS Req. 3.4 breach and effectively a full CDE compromise."
                ),
            ),
            SensitiveResource(
                name="Payments KMS keys",
                arn_patterns=[
                    "arn:aws:kms:*:*:alias/payments-*",
                    # Statements sometimes reference the alias via condition or
                    # the raw key ARN tagged to the payments aliases; both are
                    # caught because the alias glob is matched bidirectionally.
                ],
                blast_radius=(
                    "Controls the KMS keys that encrypt cardholder data at rest. "
                    "Decrypt/Encrypt access here means an attacker can read or forge "
                    "encrypted PANs, defeating PCI DSS Req. 3.5/3.6 key-management "
                    "controls."
                ),
            ),
        ]
    )

    # Resource prefixes that are explicitly NON-production. Wildcard access
    # scoped only to these is downgraded to LOW/INFORMATIONAL — this is the
    # core of the noise-reduction strategy.
    non_production_patterns: list[str] = field(
        default_factory=lambda: [
            "arn:aws:secretsmanager:*:*:secret:dev/*",
            "arn:aws:secretsmanager:*:*:secret:staging/*",
            "arn:aws:secretsmanager:*:*:secret:sandbox/*",
            "arn:aws:kms:*:*:alias/dev-*",
        ]
    )

    # Read/write actions on secrets & KMS we consider sensitive.
    sensitive_actions: list[str] = field(
        default_factory=lambda: [
            "secretsmanager:GetSecretValue",
            "secretsmanager:GetSecret*",
            "secretsmanager:DescribeSecret",
            "secretsmanager:PutSecretValue",
            "secretsmanager:UpdateSecret",
            "secretsmanager:DeleteSecret",
            "kms:Decrypt",
            "kms:Encrypt",
            "kms:GenerateDataKey",
            "kms:GenerateDataKey*",
            "kms:ReEncrypt*",
        ]
    )

    # --- B. Trust policy ------------------------------------------------
    # Account IDs we own / trust. Cross-account trust to anything NOT in
    # this set, granted to ``:root`` without conditions, is a finding.
    trusted_account_ids: list[str] = field(
        default_factory=lambda: ["111122223333", "444455556666"]
    )

    # --- C. Mitigating condition keys -----------------------------------
    # Presence of any of these (with a real value) on a statement is treated
    # as a network/identity guardrail strong enough to downgrade risk.
    mitigating_condition_keys: list[str] = field(
        default_factory=lambda: [
            "aws:SourceVpc",
            "aws:SourceVpce",
            "aws:SourceIp",
            "aws:VpcSourceIp",
            "aws:PrincipalOrgID",
        ]
    )

    # --- D. Privilege-escalation primitives -----------------------------
    # iam:PassRole on broad resources is the pivot; pairing it with any of
    # these "environment-altering" actions forms an escalation chain.
    escalation_companion_actions: list[str] = field(
        default_factory=lambda: [
            "iam:CreateRole",
            "iam:AttachRolePolicy",
            "iam:PutRolePolicy",
            "iam:CreatePolicyVersion",
            "iam:UpdateAssumeRolePolicy",
            "sts:AssumeRole",
            "lambda:CreateFunction",
            "ec2:RunInstances",
        ]
    )

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "AnalyzerConfig":
        """Build a config from a parsed YAML/JSON dict, falling back to
        defaults for any unspecified field. Unknown keys are ignored so an
        override file can be partial."""
        if not data:
            return cls()
        cfg = cls()
        if "sensitive_resources" in data:
            cfg.sensitive_resources = [
                SensitiveResource(**sr) for sr in data["sensitive_resources"]
            ]
        for simple in (
            "non_production_patterns",
            "sensitive_actions",
            "trusted_account_ids",
            "mitigating_condition_keys",
            "escalation_companion_actions",
        ):
            if simple in data:
                setattr(cfg, simple, list(data[simple]))
        return cfg
