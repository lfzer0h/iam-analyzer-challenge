"""Domain models shared across the analyzer.

These dataclasses are intentionally free of business logic. They are the
contract between the engine (which produces findings) and the reporter
(which renders them), which keeps both sides independently testable.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    """Ordered severity scale.

    Modeled as ``IntEnum`` so findings sort naturally (highest first) and
    so mitigations can *downgrade* a finding by simple arithmetic/clamping
    rather than ad-hoc string mapping.
    """

    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return {
            Severity.INFORMATIONAL: "Informational",
            Severity.LOW: "Low",
            Severity.MEDIUM: "Medium",
            Severity.HIGH: "High",
            Severity.CRITICAL: "Critical",
        }[self]

    def downgraded(self, steps: int = 1) -> "Severity":
        """Return a severity lowered by ``steps`` levels, clamped at INFORMATIONAL."""
        return Severity(max(Severity.INFORMATIONAL, self - steps))


class FindingType(str, enum.Enum):
    """Stable identifiers for each rule family. Used as grouping keys."""

    PCI_SENSITIVE_ACCESS = "pci_sensitive_data_access"
    INSECURE_TRUST_POLICY = "insecure_trust_policy"
    PRIVILEGE_ESCALATION = "privilege_escalation_chain"
    # Defense-in-depth gap: role touches CDE resources but has no permission
    # boundary capping its maximum effective permissions.
    MISSING_PERMISSION_BOUNDARY = "missing_permission_boundary"


@dataclass
class PolicyStatement:
    """A normalized IAM statement.

    Raw IAM documents are wildly polymorphic (``Action`` can be a string or
    a list; ``Resource`` likewise; ``Condition`` is deeply nested). The
    parser collapses every statement into this shape so the engine never
    has to branch on input quirks.
    """

    effect: str
    actions: list[str]
    resources: list[str]
    condition: dict[str, Any] = field(default_factory=dict)
    # Provenance: where this statement came from, so we can attribute a
    # finding to a shared managed policy and build remediation campaigns.
    source_type: str = "inline"  # "inline" | "managed"
    source_name: str = ""  # policy name
    source_arn: str | None = None  # managed policy ARN, if any

    @property
    def is_allow(self) -> bool:
        return self.effect.lower() == "allow"


@dataclass
class Finding:
    """A single risk observation about one role."""

    role_name: str
    role_arn: str
    finding_type: FindingType
    title: str
    severity: Severity
    base_severity: Severity
    blast_radius: str
    remediation: str
    # The IAM policy block (as a dict) we recommend as a least-privilege
    # replacement. Rendered verbatim into the report.
    remediation_policy: dict[str, Any] | None = None
    mitigations: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    # Campaign grouping signals (stretch goal). A finding can be consolidated
    # with others that share *any* of these, in priority order:
    #   1. shared_policy_arn   – same attached managed policy
    #   2. shared_policy_name  – same source policy name (e.g. an inline
    #                            "SharedLaxSecretsPolicy" copy-pasted around)
    #   3. policy_fingerprint  – byte-identical permission declaration
    shared_policy_arn: str | None = None
    shared_policy_name: str | None = None
    policy_fingerprint: str | None = None

    @property
    def was_mitigated(self) -> bool:
        return self.severity < self.base_severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "role_name": self.role_name,
            "role_arn": self.role_arn,
            "finding_type": self.finding_type.value,
            "title": self.title,
            "severity": self.severity.label,
            "base_severity": self.base_severity.label,
            "was_mitigated": self.was_mitigated,
            "mitigations": self.mitigations,
            "blast_radius": self.blast_radius,
            "remediation": self.remediation,
            "remediation_policy": self.remediation_policy,
            "evidence": self.evidence,
            "shared_policy_arn": self.shared_policy_arn,
            "shared_policy_name": self.shared_policy_name,
            "policy_fingerprint": self.policy_fingerprint,
        }


@dataclass
class RemediationCampaign:
    """A consolidated remediation for findings that share a root cause.

    When several roles inherit the same lax policy (or carry byte-identical
    permission declarations), emitting one alert per role is noise. The
    engine folds those into a campaign that points engineering at the single
    central resource to fix.
    """

    campaign_id: str
    title: str
    description: str
    finding_type: FindingType
    severity: Severity
    affected_roles: list[str]
    remediation: str
    # Human-readable identifier of the shared root cause: a managed policy
    # ARN, a policy name, or a "fingerprint:" label for identical inline
    # declarations. Kept as ``policy_arn`` for backward compatibility.
    policy_arn: str = ""
    remediation_policy: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "title": self.title,
            "description": self.description,
            "finding_type": self.finding_type.value,
            "severity": self.severity.label,
            "root_cause": self.policy_arn,
            "policy_arn": self.policy_arn,
            "affected_roles": self.affected_roles,
            "role_count": len(self.affected_roles),
            "remediation": self.remediation,
            "remediation_policy": self.remediation_policy,
        }
