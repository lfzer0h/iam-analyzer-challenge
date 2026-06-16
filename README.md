# IAM Contextual Risk Analyzer

**Blast-radius–aware** static analyzer for AWS IAM exports, tuned for the production environment
of a global payment gateway under PCI DSS.

The single design goal: **distinguish a role that _seems_ dangerous from one that _really is_
dangerous in context.** A wildcard (`*`) over `dev/*` is noise; an apparently harmless
`iam:PassRole` combined with `iam:CreateRole` is an account takeover path. The tool reasons about
that difference rather than simply searching for asterisks.

---

## Installation and Quick Start (< 2 minutes)

Requires **Python 3.10+**. The engine uses only stdlib; `PyYAML` is installed for the optional
`--config` argument.

```bash
# 1. Virtual environment and dependency installation — pick one:

## Option A: pip
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

## Option B: uv (https://docs.astral.sh/uv/)
uv venv && source .venv/bin/activate
uv pip install -r requirements.txt
# ...or skip venv activation entirely and prefix every command below with `uv run`,
# e.g. `uv run python main.py --input ... --output ...` / `uv run pytest -q`.

# 2. Run against the included fixture (any of the three equivalent forms)
python main.py          --input fixtures/account-export-example.json --output reports/
python -m analyzer      --input fixtures/account-export-example.json --output reports/
iam-analyzer            --input fixtures/account-export-example.json --output reports/  # requires pip install -e .

# 3. Inspect generated output
cat reports/report.md        # human-readable (Markdown with HCL)
cat reports/findings.json    # structured (CI/CD / integrations)

# 4. Browse pre-generated sample output (no tool execution required)
cat sample-output/report.md
cat sample-output/findings.json

# 5. Run tests
pytest -q
```

**Expected output when run against the included fixture:**

```
Analyzed 27 role(s): 32 finding(s) (10 critical, 6 high).
  markdown: reports/report.md
  json: reports/findings.json
```

---

### CLI Parameters

| Argument | Alias | Required | Description |
|---|---|---|---|
| `--input` | `-i` | ✅ | Path to the IAM export JSON |
| `--output` | `-o` | — | Output directory (default: `./reports`) |
| `--config` | `-c` | — | YAML file with analysis context overrides |
| `--fail-on` | — | — | Severity threshold for exit code `1` (values: `critical`, `high`, `medium`, `low`) |

---

### CI/CD Usage (`--fail-on`)

```bash
python main.py -i export.json -o reports/ --fail-on high
# Returns exit code 1 if any finding is High or above.
# Useful as a gate before a production deployment.
```

---

### Analysis Context Customization (`--config`)

Everything business-specific (sensitive secret prefixes, trusted accounts, KMS aliases,
mitigating condition keys) lives in `analyzer/config.py` and can be partially overridden
with a YAML file, without touching the engine.

A complete reference file is included in the repository as `context-example.yaml`. Example usage:

```bash
python main.py -i export.json --config context-example.yaml
```

Overridable fields:

```yaml
trusted_account_ids:          # your own accounts (avoids cross-account false positives)
non_production_patterns:      # non-prod ARN globs (downgrade severity to Informational)
sensitive_resources:          # PCI crown jewels (name + arn_patterns + blast_radius)
sensitive_actions:            # actions that count as "touches secrets/KMS"
mitigating_condition_keys:    # condition keys that reduce severity (VPC, IP, OrgID…)
escalation_companion_actions: # actions that turn PassRole into an escalation chain
```

---

## Test Fixture (`fixtures/account-export-example.json`)

The fixture uses the real `aws iam get-account-authorization-details` format (`RoleDetailList`
section + `Policies` section with resolvable version documents). It contains **27 roles**
covering three principal types: human-assumable roles via SAML/Okta, service roles (EC2, Lambda,
ECS, Glue, CodeBuild), and cross-account trust.

### Ambiguity Scenarios Illustrated

The table below highlights the **specific ambiguity** each role (or role group) was designed to
test — it is a curated sample, not an enumeration of all 32 findings the tool actually emits
against this fixture. See [Finding Count Reconciliation](#finding-count-reconciliation) below for
the exhaustive, traceable breakdown.

| # | Role(s) | Misconfiguration | Expected result |
|---|---|---|---|
| 1 | `tokenization-service` | `secretsmanager:*` on `prod/tokenization/*`, no boundary | **Critical** PCI |
| 2 | `payments-kms-admin` | `kms:Encrypt/Decrypt` on `payments-settlement` with no mitigation | **Critical** PCI |
| 3 | `ci-deployer` | `iam:PassRole(*) + iam:CreateRole + iam:AttachRolePolicy` | **Critical** escalation |
| 4 | `legacy-cron` | `Principal: "*"` in trust policy | **Critical** trust |
| 5 | `data-warehouse-sync`, `reporting-etl`, `fraud-scoring-batch` | Inherit `LegacyBroadSecretsAccess` (`secretsmanager:*` on `*`) | **CAMP-001** Critical |
| 6 | `external-analytics-bridge` | Cross-account trust to `999988887777` with no condition | **High** trust |
| 7 | `kms-rotation-lambda` | `kms:*` on `payments-*` **+ `ProdNetworkBoundary` that caps it** | base Critical → **Medium** mitigated |
| 8 | `checkout-router` | `secretsmanager:GetSecretValue` on `prod/providers/*` **+ `aws:SourceVpc`** | base High → **Medium** mitigated |
| 9 | `dev-sandbox-tester` | `secretsmanager:*` **scoped to `dev/*` only** | **Informational** (outside CDE) |
| 10 | `settlement-batch` | scoped `iam:PassRole` + `iam:PassedToService` condition | **no finding** (true negative) |
| 11 | `backup-vault-role` | `backup:*` on `*` | **no finding** (`backup:*` is not a sensitive action) |
| 12 | `merchant-onboarding` + `merchant-onboarding-service-v2` | Same `SharedLaxSecretsPolicy` inline in both roles | **CAMP-002** High |
| 13 | PCI roles without boundary | `checkout-router`, `tokenization-service`, `refund-processor`… | **Medium** `missing_permission_boundary` |

**Intentional ambiguity** is in cases 7–11: roles that appear lethal but are correctly controlled,
and roles that look clean but hide dangerous chains. Designing the fixture to capture that ambiguity
is part of the challenge.

> Rows 1, 2, 8, and 13 overlap on purpose: a role that touches a PCI resource *and* lacks a
> permission boundary triggers **two** independent findings — `pci_sensitive_data_access` (rule A)
> and `missing_permission_boundary` (rule E). That overlap, multiplied across 19 affected roles
> plus the two campaigns, is why the fixture's real total (32) is larger than the 13 rows above.

### Finding Count Reconciliation

Running the analyzer against this fixture produces:

```
Analyzed 27 role(s): 32 finding(s) (10 critical, 6 high).
```

**By severity** (`findings.json` → `summary.by_severity`):

| Severity | Count |
|---|---|
| Critical | 10 |
| High | 6 |
| Medium | 15 |
| Low | 0 |
| Informational | 1 |
| **Total** | **32** |

**By rule (finding type):**

| Finding type | Count | Severities present |
|---|---|---|
| `privilege_escalation_chain` | 3 | Critical ×3 |
| `insecure_trust_policy` | 2 | Critical ×1, High ×1 |
| `pci_sensitive_data_access` | 15 | Critical ×6, High ×5, Medium ×3, Informational ×1 |
| `missing_permission_boundary` | 12 | Medium ×12 |

**By consolidation** (campaigns vs. standalone — `findings.json` → `remediation_campaigns` / `findings`):

| | Findings | Roles |
|---|---|---|
| Folded into `CAMP-001` (`LegacyBroadSecretsAccess`) | 3 | `data-warehouse-sync`, `fraud-scoring-batch`, `reporting-etl` |
| Folded into `CAMP-002` (`SharedLaxSecretsPolicy`) | 2 | `merchant-onboarding`, `merchant-onboarding-service-v2` |
| Listed individually under `findings` | 27 | 19 distinct roles (several carry 2+ findings each) |
| **Total** | **32** | — |

**Role coverage:** 19 of the 27 fixture roles (≈70%) produce at least one finding. The remaining 8
are deliberate true negatives, each locked in by a dedicated assertion in `tests/test_engine.py`:
`partner-settlement-reader`, `webhook-dispatcher`, `settlement-batch`, `observability-agent`,
`support-readonly-human`, `lambda-edge-config`, `backup-vault-role`, `open-data-publisher`.

---

## Architecture

```
iam-challenge/
├── analyzer/
│   ├── __init__.py
│   ├── __main__.py      # python -m analyzer
│   ├── cli.py           # argparse: --input / --output / --config / --fail-on
│   ├── config.py        # business context (PCI crown jewels, accounts, mitigants)
│   ├── engine.py        # 4 detection rules + inline contextual mitigation
│   ├── models.py        # Severity, Finding, RemediationCampaign, PolicyStatement
│   ├── parser.py        # robust ingestion and validation of malformed JSON
│   └── reporter.py      # Markdown + JSON + Terraform HCL + campaigns
├── fixtures/
│   └── account-export-example.json   # 27 roles with intentional ambiguity
├── sample-output/
│   ├── report.md             # pre-generated output (readable without running)
│   └── findings.json         # pre-generated output (structured)
├── tests/
│   └── test_engine.py        # 26 tests locking each contextual decision
├── context-example.yaml      # complete reference configuration overrides
├── main.py                   # executable entry point
├── pyproject.toml
└── requirements.txt
```

**Separation of concerns:**

| Module | Question it answers |
|---|---|
| `parser.py` | Is this file a valid IAM export? |
| `config.py` | What is sensitive *in this environment*? |
| `engine.py` | Is this role dangerous *in context*? |
| `reporter.py` | How do I present the result to a human and a machine? |

The critical separation is **`config` (context) ↔ `engine` (logic)**: the engine contains no
business-specific literals. It receives context as a parameter, making it independently testable
and reusable by another organization that only changes `config.py`.

---

## Stretch Goals

### 1. Terraform Ready for PR

Each finding in `report.md` and in `findings.json` includes a dynamically generated HCL block
under the `remediation_terraform` key. The Terraform resource type varies by finding type:

| Finding type | Generated Terraform resource(s) |
|---|---|
| `pci_sensitive_data_access` | `aws_iam_policy` + `aws_iam_role_policy_attachment` |
| `privilege_escalation_chain` | `aws_iam_policy` + `aws_iam_role_policy_attachment` |
| `insecure_trust_policy` | `aws_iam_role { assume_role_policy }` + `terraform import` instruction |
| `missing_permission_boundary` | `aws_iam_policy` (boundary) + `aws_iam_role { permissions_boundary }` |

Example generated block for a PCI access finding:

```hcl
resource "aws_iam_policy" "remediated_checkout_router_pci_sensitive_data_access" {
  name        = "yuno-remediated-checkout_router"
  description = "Least-privilege policy — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = ["arn:aws:secretsmanager:*:*:secret:prod/providers/*"]
        Condition = {
          StringEquals = {
            "aws:SourceVpc" = "vpc-REPLACE_WITH_PROD_VPC"
          }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "remediated_checkout_router_pci_sensitive_data_access" {
  role       = "checkout-router"  # replace with your tf resource reference
  policy_arn = aws_iam_policy.remediated_checkout_router_pci_sensitive_data_access.arn
}
```

> **KMS Note:** AWS identity policies do not resolve wildcards on KMS alias strings for
> cryptographic operations. When the finding involves KMS, the generated resource uses
> `arn:aws:kms:*:*:key/*` and the `remediation` field includes a clarifying note to replace it
> with the actual key UUID before applying.

### 2. Remediation Campaigns

When multiple roles share the same root cause, the tool consolidates them into a
**Remediation Campaign** instead of emitting redundant per-role alerts.

**Grouping criteria** (in priority order):

1. **Shared managed policy ARN** — same `arn:aws:iam::ACCOUNT:policy/Name` attached to multiple roles
2. **Byte-identical permission declaration** (SHA-1 fingerprint of `effect+actions+resources`) — covers inline policies copy-pasted under different names

The campaign generates a Terraform block with **one `aws_iam_policy`** and
**N `aws_iam_role_policy_attachment`** resources — a single `terraform apply` closes all affected
roles:

```hcl
# CAMP-001 — Fixes 3 roles in one apply
resource "aws_iam_policy" "remediated_camp_001" { ... }

resource "aws_iam_role_policy_attachment" "remediated_camp_001_data_warehouse_sync" {
  role       = "data-warehouse-sync"
  policy_arn = aws_iam_policy.remediated_camp_001.arn
}
# ... one entry per affected role
```

The fixture includes two demonstration campaigns:

| ID | Root cause | Affected roles | Severity |
|---|---|---|---|
| `CAMP-001` | `LegacyBroadSecretsAccess` (managed policy) | `data-warehouse-sync`, `fraud-scoring-batch`, `reporting-etl` | Critical |
| `CAMP-002` | `SharedLaxSecretsPolicy` (identical inline name) | `merchant-onboarding`, `merchant-onboarding-service-v2` | High |

---

## Security Reasoning

### 1. Which misconfiguration classes were prioritized, and why?

In a card processor the relevant asset is not "the AWS account" in the abstract, but the
**Cardholder Data Environment (CDE)**. The four classes with a direct line to the PAN and to
money-movement credentials were therefore prioritized:

1. **Access to PCI crown jewels** — Secrets Manager `prod/providers/*` and `prod/tokenization/*`,
   KMS `payments-*`. Compromising the tokenization vault is effectively detokenizing PANs — a
   reportable PCI DSS Req. 3.4 breach and the worst possible outcome, so it receives the most
   aggressive severity treatment.

2. **Insecure trust relationships.** The most careful access control is worthless if a third party
   can _assume_ the role that touches the data. A `Principal: "*"` or an unconditioned `:root`
   cross-account trust turns any permission in the role into an attacker's permission
   (confused-deputy pattern). Evaluated entirely separately from policy content.

3. **Privilege-escalation chains.** `iam:PassRole(*)` combined with `iam:CreateRole` /
   `iam:AttachRolePolicy` allows minting an admin role and handing it to a service — full account
   takeover, _independent_ of how scoped each individual line looks. This is the class a naive
   wildcard scanner will not detect.

4. **Missing permission boundary on CDE roles** — defense-in-depth control (PCI DSS Req. 7).
   Without a boundary, any future attached policy — accidental or malicious — becomes effective
   immediately. The risk is not the _current_ access but the _future_ silent escalation window.
   Deliberately set at Medium severity so it does not overshadow direct-access findings.

Key exclusions: access-key rotation, password policy, per-user MFA — important hygiene, but not
the difference between "audit passed" and "card breach".

### 2. How does the tool handle ambiguous cases?

Mitigation is **not a post-processing step** but part of the severity calculation, so the final
number always reflects the real post-control risk.

**Signals that reduce severity:**

- **`aws:SourceVpc` / `aws:SourceVpce` / `aws:SourceIp` on the same statement** → the credential
  is only usable from inside the production network → −1 level.
  _(`checkout-router`: base High → Medium.)_
- **Permission boundary that actually caps:** the engine resolves the boundary document and
  verifies it grants no wildcards. If the boundary limits to rotation actions, a `kms:*` policy is
  effectively inert → −2 levels. _(`kms-rotation-lambda`: base Critical → Medium.)_ If the
  boundary exists but is not in the export (opaque), credit of −1 level: presence confirmed, scope
  unverifiable. _(`db-migration-runner`.)_
- **Resource exclusively non-prod** (`dev/*`, `staging/*`, `sandbox/*`) → outside the CDE →
  Informational. _(`dev-sandbox-tester`.)_
- **Trust with origin condition** toward an owned account → not a finding.
  _(`partner-settlement-reader`: trusted account + `sts:ExternalId` → clean.)_

**Signals that maintain or raise an alert despite clean appearance:**

- `Resource: "*"` reaches the PCI crown jewels through bidirectional wildcard matching.
- Cross-account trust to an account not listed as owned, without a condition.
- Co-occurrence of `iam:PassRole(broad)` + `iam:CreateRole` even when each individual statement
  looks reasonable.

### 3. Where were false positives accepted, and where were controlled false negatives chosen?

**Accepted false positives (coverage over precision):**

- `Resource: "*"` is always treated as reaching the crown jewels. In a payments environment the
  cost of an extra alert is trivial compared to a leaked PAN.
- `break-glass-admin` is flagged Critical even though it is a legitimate emergency role with
  mandatory MFA. A human must confirm "yes, this is intentional".
- Bidirectional case-insensitive wildcard matching: deliberate over-approximation that guarantees
  no real overlap is missed.

**Controlled false negatives (precision over coverage):**

- Wildcards for non-sensitive services (`backup:*`, `logs:*`, `cloudwatch:*`) do not trigger the
  PCI rule even when their `Resource` is `*`. The dual gate (sensitive action **and** resource that
  reaches PCI) prevents alert fatigue that trains teams to ignore the report.
- Explicit `Deny` statements are not evaluated. A `Deny` that would negate a dangerous `Allow` is
  not cross-checked yet — known gap documented in §4.
- Opaque permission boundary = partial credit (−1 level, not −2). Without reading the document,
  no full protection is assumed.

Governing rule: **on the path to the CDE, bias toward the false positive; everywhere else, bias
toward precision** to preserve report credibility.

### 4. What would you build next? What residual risk does the tool not cover today?

**Next steps in order of value:**

1. **Full Allow/Deny evaluation:** cross-check `Allow` statements against explicit `Deny` and
   `NotAction`/`NotResource` to compute _effective_ permission, not declared permission.
2. **AWS Organizations SCPs:** a permission may be correctly restricted by an SCP at the OU level
   that the analyzer cannot see, generating false positives. Ingesting the SCP tree would close
   that gap.
3. **Resource-based policies** (S3 bucket policies, KMS key policies, secret policies). Real
   access is the _intersection_ of the identity policy and the resource policy; today only the
   first half is examined.
4. **End-to-end PassRole resolution:** follow which concrete roles the principal can pass, and
   what those target roles can do, to score the actual depth of the chain.
5. **Integration with IAM Access Analyzer:** validate cross-account trust against the principals
   that actually exercise it in real time.

**Residual risks the analyzer does NOT cover today** (note in audit report): organizational SCPs,
resource-based policies (S3/KMS/SQS), session policies, tag conditions (`aws:ResourceTag`),
misconfigured OIDC/SAML federation at the IdP level, and implicit service permissions (e.g., a
Lambda role that accesses KMS via the service API without declaring it in its policy).

Current scope: **role identity policies** — the first and highest-signal link in a payments
environment, but not the complete picture of effective access in AWS.
