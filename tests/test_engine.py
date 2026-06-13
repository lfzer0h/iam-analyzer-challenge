"""Engine behavior tests.

These lock in the *contextual* decisions — the whole point of the tool.
Each test names the ambiguity it guards so a regression reads clearly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from analyzer.engine import SecurityEngine, _patterns_overlap
from analyzer.models import FindingType, Severity
from analyzer.parser import ParserError, parse_document
from analyzer.reporter import build_campaigns

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "account-export-example.json"


@pytest.fixture(scope="module")
def findings_by_role():
    account = parse_document(json.loads(FIXTURE.read_text()))
    findings = SecurityEngine().analyze(account.roles, account.managed_policies)
    by_role: dict[str, list] = {}
    for f in findings:
        by_role.setdefault(f.role_name, []).append(f)
    return by_role


def _of_type(findings, ftype):
    return [f for f in findings if f.finding_type == ftype]


# --- pattern matching --------------------------------------------------- #
def test_bidirectional_overlap():
    # statement "prod/*" must be seen to reach sensitive "prod/providers/*"
    assert _patterns_overlap("arn:...secret:prod/*", "arn:...secret:prod/providers/*")
    # and the reverse direction (specific statement, wildcard sensitive)
    assert _patterns_overlap("arn:...secret:prod/tokenization/card", "arn:...secret:prod/tokenization/*")
    # unrelated namespaces don't collide
    assert not _patterns_overlap("arn:...secret:dev/*", "arn:...secret:prod/providers/*")


# --- crown jewels, real danger ----------------------------------------- #
def test_tokenization_wildcard_is_critical(findings_by_role):
    f = _of_type(findings_by_role["tokenization-service"], FindingType.PCI_SENSITIVE_ACCESS)[0]
    assert f.severity == Severity.CRITICAL
    assert not f.was_mitigated


# --- looks dangerous, is fenced (the noise-reduction cases) ------------ #
def test_sourcevpc_condition_downgrades(findings_by_role):
    f = _of_type(findings_by_role["checkout-router"], FindingType.PCI_SENSITIVE_ACCESS)[0]
    assert f.was_mitigated
    assert f.severity < Severity.HIGH
    assert any("condition_keys" in m for m in f.mitigations)


def test_permission_boundary_caps_kms_wildcard(findings_by_role):
    # kms:* on payments alias, but boundary grants no wildcard -> hard cap.
    f = _of_type(findings_by_role["kms-rotation-lambda"], FindingType.PCI_SENSITIVE_ACCESS)[0]
    assert f.base_severity == Severity.CRITICAL
    assert f.severity <= Severity.MEDIUM
    assert any("permission_boundary_caps" in m for m in f.mitigations)


def test_dev_only_wildcard_is_informational(findings_by_role):
    f = _of_type(findings_by_role["dev-sandbox-tester"], FindingType.PCI_SENSITIVE_ACCESS)[0]
    assert f.severity == Severity.INFORMATIONAL


# --- looks clean, is dangerous (the unmasking cases) ------------------- #
def test_wildcard_trust_principal_is_critical(findings_by_role):
    f = _of_type(findings_by_role["legacy-cron"], FindingType.INSECURE_TRUST_POLICY)[0]
    assert f.severity == Severity.CRITICAL


def test_untrusted_cross_account_root_is_high(findings_by_role):
    f = _of_type(findings_by_role["external-analytics-bridge"], FindingType.INSECURE_TRUST_POLICY)[0]
    assert f.severity == Severity.HIGH


def test_hidden_passrole_escalation(findings_by_role):
    f = _of_type(findings_by_role["ci-deployer"], FindingType.PRIVILEGE_ESCALATION)[0]
    assert f.severity == Severity.CRITICAL


def test_create_attach_without_passrole_is_escalation(findings_by_role):
    assert _of_type(findings_by_role["iam-self-service"], FindingType.PRIVILEGE_ESCALATION)


# --- true negatives (precision guards) --------------------------------- #
def test_scoped_passrole_is_not_escalation(findings_by_role):
    assert "settlement-batch" not in findings_by_role


def test_unrelated_service_wildcard_not_pci(findings_by_role):
    # backup:* on * must NOT produce any findings — neither PCI access nor
    # missing-boundary (the action gate filters it before touching resources).
    assert not findings_by_role.get("backup-vault-role", [])


def test_trusted_account_with_externalid_is_clean(findings_by_role):
    assert "partner-settlement-reader" not in findings_by_role


# --- campaigns ---------------------------------------------------------- #
def test_shared_lax_policy_forms_one_campaign(findings_by_role):
    all_findings = [f for fs in findings_by_role.values() for f in fs]
    campaigns, _ = build_campaigns(all_findings)
    legacy = [c for c in campaigns if c.policy_arn.endswith("LegacyBroadSecretsAccess")]
    assert len(legacy) == 1
    assert set(legacy[0].affected_roles) == {
        "data-warehouse-sync", "reporting-etl", "fraud-scoring-batch"
    }


def test_campaign_is_populated_not_empty(findings_by_role):
    all_findings = [f for fs in findings_by_role.values() for f in fs]
    campaigns, _ = build_campaigns(all_findings)
    assert campaigns, "remediation_campaigns must not be empty"
    c = campaigns[0]
    # The four schema fields the JSON/MD consumers rely on.
    assert c.campaign_id == "CAMP-001"
    assert c.title
    assert c.description
    assert c.affected_roles


def test_identical_inline_declarations_consolidate_without_managed_arn():
    """Two roles with byte-identical *inline* lax policies (no managed ARN,
    different policy names) must still collapse into one campaign."""
    lax = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "secretsmanager:*",
                        "Resource": "arn:aws:secretsmanager:*:*:secret:prod/providers/*"}],
    }
    doc = {"RoleDetailList": [
        {"RoleName": "svc-a", "Arn": "arn:aws:iam::1:role/svc-a",
         "AssumeRolePolicyDocument": {}, "AttachedManagedPolicies": [],
         "RolePolicyList": [{"PolicyName": "copy-paste-a", "PolicyDocument": lax}]},
        {"RoleName": "svc-b", "Arn": "arn:aws:iam::1:role/svc-b",
         "AssumeRolePolicyDocument": {}, "AttachedManagedPolicies": [],
         "RolePolicyList": [{"PolicyName": "copy-paste-b", "PolicyDocument": lax}]},
    ]}
    account = parse_document(doc)
    findings = SecurityEngine().analyze(account.roles, account.managed_policies)
    campaigns, _ = build_campaigns(findings)
    assert len(campaigns) == 1
    assert set(campaigns[0].affected_roles) == {"svc-a", "svc-b"}


def test_kms_remediation_uses_key_arn_not_alias(findings_by_role):
    f = _of_type(findings_by_role["payments-kms-admin"], FindingType.PCI_SENSITIVE_ACCESS)[0]
    resources = f.remediation_policy["Resource"]
    assert "arn:aws:kms:*:*:key/*" in resources
    assert all("alias/payments-" not in r for r in resources)
    assert "do not natively resolve wildcards on KMS alias" in f.remediation


def test_shared_inline_policy_name_forms_camp002(findings_by_role):
    """merchant-onboarding and merchant-onboarding-service-v2 both carry the
    same inline policy 'SharedLaxSecretsPolicy' — they must collapse into a
    second campaign distinct from the LegacyBroadSecretsAccess one."""
    all_findings = [f for fs in findings_by_role.values() for f in fs]
    campaigns, _ = build_campaigns(all_findings)
    shared = [c for c in campaigns if c.policy_arn == "SharedLaxSecretsPolicy"]
    assert len(shared) == 1, "Expected exactly one CAMP for SharedLaxSecretsPolicy"
    assert set(shared[0].affected_roles) == {
        "merchant-onboarding", "merchant-onboarding-service-v2"
    }
    assert shared[0].campaign_id == "CAMP-002"
    assert "2 roles" in shared[0].description


def test_secrets_only_finding_has_no_kms_note(findings_by_role):
    # refund-processor touches only Secrets Manager -> no KMS caveat leakage.
    f = _of_type(findings_by_role["refund-processor"], FindingType.PCI_SENSITIVE_ACCESS)[0]
    assert "KMS alias" not in f.remediation


# --- E. Missing permission boundary --------------------------------------- #
def test_pci_role_without_boundary_gets_medium_finding(findings_by_role):
    """tokenization-service touches prod/tokenization/* and has no boundary
    → must produce a MISSING_PERMISSION_BOUNDARY finding at MEDIUM."""
    findings = _of_type(
        findings_by_role["tokenization-service"], FindingType.MISSING_PERMISSION_BOUNDARY
    )
    assert findings, "Expected missing-boundary finding on tokenization-service"
    f = findings[0]
    assert f.severity == Severity.MEDIUM
    assert not f.was_mitigated
    assert f.remediation_policy is not None


def test_role_with_caps_boundary_has_no_missing_boundary_finding(findings_by_role):
    """kms-rotation-lambda has ProdNetworkBoundary → boundary gap is closed,
    no MISSING_PERMISSION_BOUNDARY finding should fire."""
    findings = _of_type(
        findings_by_role.get("kms-rotation-lambda", []),
        FindingType.MISSING_PERMISSION_BOUNDARY,
    )
    assert not findings


def test_non_pci_role_has_no_missing_boundary_finding(findings_by_role):
    """webhook-dispatcher and observability-agent touch no PCI resources
    → missing-boundary rule must NOT fire for them (avoid false positives)."""
    for role in ("webhook-dispatcher", "observability-agent"):
        findings = _of_type(
            findings_by_role.get(role, []),
            FindingType.MISSING_PERMISSION_BOUNDARY,
        )
        assert not findings, f"False positive: {role} got missing-boundary finding"


def test_opaque_boundary_still_suppresses_gap_finding(findings_by_role):
    """db-migration-runner has an *opaque* boundary (not exported). The rule
    still credits the ARN's presence — no MISSING_PERMISSION_BOUNDARY fires."""
    findings = _of_type(
        findings_by_role.get("db-migration-runner", []),
        FindingType.MISSING_PERMISSION_BOUNDARY,
    )
    assert not findings


def test_missing_boundary_finding_has_terraform_block(findings_by_role):
    """Each missing-boundary finding must carry a Terraform block with
    permissions_boundary attribute (not aws_iam_role_policy_attachment)."""
    from analyzer.reporter import build_campaigns, _render_finding_terraform

    all_f = [f for fs in findings_by_role.values() for f in fs]
    _, standalone = build_campaigns(all_f)
    boundary_findings = [
        f for f in standalone
        if f.finding_type == FindingType.MISSING_PERMISSION_BOUNDARY
    ]
    assert boundary_findings, "Need at least one standalone boundary finding"
    sample = boundary_findings[0]
    tf = _render_finding_terraform(sample)
    assert tf is not None
    assert "permissions_boundary" in tf
    assert "aws_iam_role_policy_attachment" not in tf


# --- parser robustness -------------------------------------------------- #
def test_parser_rejects_non_object():
    with pytest.raises(ParserError):
        parse_document([1, 2, 3])


def test_parser_rejects_missing_rolelist():
    with pytest.raises(ParserError):
        parse_document({"Policies": []})


def test_parser_skips_malformed_role_but_keeps_good_ones():
    doc = {
        "RoleDetailList": [
            {"RoleName": "ok", "Arn": "arn:aws:iam::1:role/ok",
             "AssumeRolePolicyDocument": {}, "RolePolicyList": [], "AttachedManagedPolicies": []},
            {"NoName": True},
        ]
    }
    account = parse_document(doc)
    assert len(account.roles) == 1
    assert account.warnings
