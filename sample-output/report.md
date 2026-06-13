# IAM Contextual Risk Report

> Blast-radius–aware analysis of an AWS IAM export, scoped to a PCI DSS payment-processing environment. Severities are **post-mitigation**: a finding marked _mitigated_ had its base severity lowered because a real, verified control (permission boundary, network condition, scoped resource) caps the exposure.

## Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 10 |
| 🟠 High | 6 |
| 🟡 Medium | 15 |
| 🔵 Low | 0 |
| ⚪ Informational | 1 |
| **Total** | **32** |

_6 finding(s) were downgraded by verified mitigations._

## 🎯 Campaigns of Remediation (Stretch Goals)

Multiple roles share the **same root cause** (a common managed policy, a reused policy name, or a byte-identical permission declaration). Fixing the central policy once resolves every listed role — do this before chasing the per-role findings below.

### CAMP-001 — `arn:aws:iam::111122223333:policy/LegacyBroadSecretsAccess`

- **Severity:** 🔴 Critical
- **Finding type:** `pci_sensitive_data_access`
- **Description:** 3 roles are exposed through the same shared managed policy (`arn:aws:iam::111122223333:policy/LegacyBroadSecretsAccess`). Remediating the central root cause once resolves all of them, instead of editing 3 roles individually.
- **Affected roles (3):** `data-warehouse-sync`, `fraud-scoring-batch`, `reporting-etl`
- **Remediation:** Fix the shared managed policy `arn:aws:iam::111122223333:policy/LegacyBroadSecretsAccess` at the source. Replace the wildcard/broad statement with a least-privilege block that (1) names only the exact secret/key ARNs the service needs, (2) drops write actions unless operationally required, and (3) adds an aws:SourceVpc (or aws:SourceVpce) guardrail so the credential is only usable from inside the production CDE network. Note: Replace the generic KMS key wildcard with your specific Key UUID ARNs during deployment, as IAM identity policies do not natively resolve wildcards on KMS alias strings for cryptographic operations.

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:*",
    "kms:Decrypt",
    "kms:GenerateDataKey"
  ],
  "Resource": [
    "arn:aws:secretsmanager:*:*:secret:prod/providers/*",
    "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*",
    "arn:aws:kms:*:*:key/*"
  ],
  "Condition": {
    "StringEquals": {
      "aws:SourceVpc": "vpc-REPLACE_WITH_PROD_VPC"
    }
  }
}
```

**Terraform (ready for PR):**

```hcl
# CAMP-001 — root cause: arn:aws:iam::111122223333:policy/LegacyBroadSecretsAccess
# Fixes 3 roles in one apply: data-warehouse-sync, fraud-scoring-batch, reporting-etl

resource "aws_iam_policy" "remediated_camp_001" {
  name        = "yuno-remediated-camp_001"
  description = "Least-privilege policy — IAM Contextual Risk Analyzer (CAMP-001)"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:*", "kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [
          "arn:aws:secretsmanager:*:*:secret:prod/providers/*",
          "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*",
          "arn:aws:kms:*:*:key/*",
        ]
        Condition = {
          StringEquals = {
            "aws:SourceVpc" = "vpc-REPLACE_WITH_PROD_VPC"
          }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "remediated_camp_001_data_warehouse_sync" {
  role       = "data-warehouse-sync"  # replace with your tf resource reference
  policy_arn = aws_iam_policy.remediated_camp_001.arn
}

resource "aws_iam_role_policy_attachment" "remediated_camp_001_fraud_scoring_batch" {
  role       = "fraud-scoring-batch"  # replace with your tf resource reference
  policy_arn = aws_iam_policy.remediated_camp_001.arn
}

resource "aws_iam_role_policy_attachment" "remediated_camp_001_reporting_etl" {
  role       = "reporting-etl"  # replace with your tf resource reference
  policy_arn = aws_iam_policy.remediated_camp_001.arn
}
```

### CAMP-002 — `SharedLaxSecretsPolicy`

- **Severity:** 🟠 High
- **Finding type:** `pci_sensitive_data_access`
- **Description:** 2 roles are exposed through the same shared policy name (`SharedLaxSecretsPolicy`). Remediating the central root cause once resolves all of them, instead of editing 2 roles individually.
- **Affected roles (2):** `merchant-onboarding`, `merchant-onboarding-service-v2`
- **Remediation:** Fix the shared policy name `SharedLaxSecretsPolicy` at the source. Replace the wildcard/broad statement with a least-privilege block that (1) names only the exact secret/key ARNs the service needs, (2) drops write actions unless operationally required, and (3) adds an aws:SourceVpc (or aws:SourceVpce) guardrail so the credential is only usable from inside the production CDE network. Note: Replace the generic KMS key wildcard with your specific Key UUID ARNs during deployment, as IAM identity policies do not natively resolve wildcards on KMS alias strings for cryptographic operations.

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:GetSecretValue",
    "secretsmanager:DescribeSecret"
  ],
  "Resource": [
    "arn:aws:secretsmanager:*:*:secret:prod/providers/*",
    "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*",
    "arn:aws:kms:*:*:key/*"
  ],
  "Condition": {
    "StringEquals": {
      "aws:SourceVpc": "vpc-REPLACE_WITH_PROD_VPC"
    }
  }
}
```

**Terraform (ready for PR):**

```hcl
# CAMP-002 — root cause: SharedLaxSecretsPolicy
# Fixes 2 roles in one apply: merchant-onboarding, merchant-onboarding-service-v2

resource "aws_iam_policy" "remediated_camp_002" {
  name        = "yuno-remediated-camp_002"
  description = "Least-privilege policy — IAM Contextual Risk Analyzer (CAMP-002)"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = [
          "arn:aws:secretsmanager:*:*:secret:prod/providers/*",
          "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*",
          "arn:aws:kms:*:*:key/*",
        ]
        Condition = {
          StringEquals = {
            "aws:SourceVpc" = "vpc-REPLACE_WITH_PROD_VPC"
          }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "remediated_camp_002_merchant_onboarding" {
  role       = "merchant-onboarding"  # replace with your tf resource reference
  policy_arn = aws_iam_policy.remediated_camp_002.arn
}

resource "aws_iam_role_policy_attachment" "remediated_camp_002_merchant_onboarding_service_v2" {
  role       = "merchant-onboarding-service-v2"  # replace with your tf resource reference
  policy_arn = aws_iam_policy.remediated_camp_002.arn
}
```

## Findings

### 1. `break-glass-admin` — Privilege-escalation chain: iam:PassRole(*) + iam:CreateRole, iam:AttachRolePolicy, iam:PutRolePolicy, iam:CreatePolicyVersion, iam:UpdateAssumeRolePolicy, sts:AssumeRole, lambda:CreateFunction, ec2:RunInstances

- **Severity:** 🔴 Critical
- **Finding type:** `privilege_escalation_chain`
- **Role ARN:** `arn:aws:iam::111122223333:role/break-glass-admin`
- **Blast radius:** This permission combination lets the principal mint or rewrite an IAM role with arbitrary policies and hand it to a compute/service principal. That is a path to full account takeover — including the tokenization vault and payments KMS keys — i.e. total CDE compromise and a catastrophic PCI DSS failure, independent of how narrow any single statement looks.
- **Remediation:** Break the chain: scope iam:PassRole to the exact service-role ARNs the workload must pass (never '*') and add an iam:PassedToService condition; remove iam:CreateRole / iam:AttachRolePolicy / iam:PutRolePolicy unless this is a provisioning role, in which case gate it behind a permission boundary that the created roles must inherit.

<details><summary>Evidence</summary>

```json
{
  "chain": "iam:PassRole(*) + iam:CreateRole, iam:AttachRolePolicy, iam:PutRolePolicy, iam:CreatePolicyVersion, iam:UpdateAssumeRolePolicy, sts:AssumeRole, lambda:CreateFunction, ec2:RunInstances",
  "companions": [
    "iam:CreateRole",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:CreatePolicyVersion",
    "iam:UpdateAssumeRolePolicy",
    "sts:AssumeRole",
    "lambda:CreateFunction",
    "ec2:RunInstances"
  ]
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "iam:PassRole"
  ],
  "Resource": [
    "arn:aws:iam::ACCOUNT:role/service-role/specific-task-role"
  ],
  "Condition": {
    "StringEquals": {
      "iam:PassedToService": "ecs-tasks.amazonaws.com"
    }
  }
}
```

**Terraform (ready for PR):**

```hcl
resource "aws_iam_policy" "remediated_break_glass_admin_privilege_escalation_chain" {
  name        = "yuno-remediated-break_glass_admin"
  description = "Least-privilege policy — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["iam:PassRole"]
        Resource = ["arn:aws:iam::ACCOUNT:role/service-role/specific-task-role"]
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "ecs-tasks.amazonaws.com"
          }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "remediated_break_glass_admin_privilege_escalation_chain" {
  role       = "break-glass-admin"  # replace with your tf resource reference
  policy_arn = aws_iam_policy.remediated_break_glass_admin_privilege_escalation_chain.arn
}
```

### 2. `break-glass-admin` — Production payment asset access: Provider credentials (Secrets Manager), Tokenization vault secrets (Secrets Manager), Payments KMS keys

- **Severity:** 🔴 Critical
- **Finding type:** `pci_sensitive_data_access`
- **Role ARN:** `arn:aws:iam::111122223333:role/break-glass-admin`
- **Blast radius:** Exposes live acquirer / PSP API credentials. An attacker could initiate or reroute settlements on behalf of the gateway, breaching PCI DSS Req. 3 (protection of stored credentials) and Req. 7 (least privilege on cardholder-data systems). Grants reach into the tokenization vault that maps tokens to PANs. Compromise enables detokenization of cardholder data — a reportable PCI DSS Req. 3.4 breach and effectively a full CDE compromise. Controls the KMS keys that encrypt cardholder data at rest. Decrypt/Encrypt access here means an attacker can read or forge encrypted PANs, defeating PCI DSS Req. 3.5/3.6 key-management controls.
- **Remediation:** Replace the wildcard/broad statement with a least-privilege block that (1) names only the exact secret/key ARNs the service needs, (2) drops write actions unless operationally required, and (3) adds an aws:SourceVpc (or aws:SourceVpce) guardrail so the credential is only usable from inside the production CDE network. Note: Replace the generic KMS key wildcard with your specific Key UUID ARNs during deployment, as IAM identity policies do not natively resolve wildcards on KMS alias strings for cryptographic operations.

<details><summary>Evidence</summary>

```json
{
  "actions": [
    "*"
  ],
  "resources": [
    "*"
  ],
  "source_type": "managed",
  "source_name": "AdministratorAccess"
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:GetSecretValue"
  ],
  "Resource": [
    "arn:aws:secretsmanager:*:*:secret:prod/providers/*",
    "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*",
    "arn:aws:kms:*:*:key/*"
  ],
  "Condition": {
    "StringEquals": {
      "aws:SourceVpc": "vpc-REPLACE_WITH_PROD_VPC"
    }
  }
}
```

**Terraform (ready for PR):**

```hcl
resource "aws_iam_policy" "remediated_break_glass_admin_pci_sensitive_data_access" {
  name        = "yuno-remediated-break_glass_admin"
  description = "Least-privilege policy — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = [
          "arn:aws:secretsmanager:*:*:secret:prod/providers/*",
          "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*",
          "arn:aws:kms:*:*:key/*",
        ]
        Condition = {
          StringEquals = {
            "aws:SourceVpc" = "vpc-REPLACE_WITH_PROD_VPC"
          }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "remediated_break_glass_admin_pci_sensitive_data_access" {
  role       = "break-glass-admin"  # replace with your tf resource reference
  policy_arn = aws_iam_policy.remediated_break_glass_admin_pci_sensitive_data_access.arn
}
```

### 3. `ci-deployer` — Privilege-escalation chain: iam:PassRole(*) + iam:CreateRole, iam:AttachRolePolicy

- **Severity:** 🔴 Critical
- **Finding type:** `privilege_escalation_chain`
- **Role ARN:** `arn:aws:iam::111122223333:role/ci-deployer`
- **Blast radius:** This permission combination lets the principal mint or rewrite an IAM role with arbitrary policies and hand it to a compute/service principal. That is a path to full account takeover — including the tokenization vault and payments KMS keys — i.e. total CDE compromise and a catastrophic PCI DSS failure, independent of how narrow any single statement looks.
- **Remediation:** Break the chain: scope iam:PassRole to the exact service-role ARNs the workload must pass (never '*') and add an iam:PassedToService condition; remove iam:CreateRole / iam:AttachRolePolicy / iam:PutRolePolicy unless this is a provisioning role, in which case gate it behind a permission boundary that the created roles must inherit.

<details><summary>Evidence</summary>

```json
{
  "chain": "iam:PassRole(*) + iam:CreateRole, iam:AttachRolePolicy",
  "companions": [
    "iam:CreateRole",
    "iam:AttachRolePolicy"
  ]
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "iam:PassRole"
  ],
  "Resource": [
    "arn:aws:iam::ACCOUNT:role/service-role/specific-task-role"
  ],
  "Condition": {
    "StringEquals": {
      "iam:PassedToService": "ecs-tasks.amazonaws.com"
    }
  }
}
```

**Terraform (ready for PR):**

```hcl
resource "aws_iam_policy" "remediated_ci_deployer_privilege_escalation_chain" {
  name        = "yuno-remediated-ci_deployer"
  description = "Least-privilege policy — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["iam:PassRole"]
        Resource = ["arn:aws:iam::ACCOUNT:role/service-role/specific-task-role"]
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "ecs-tasks.amazonaws.com"
          }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "remediated_ci_deployer_privilege_escalation_chain" {
  role       = "ci-deployer"  # replace with your tf resource reference
  policy_arn = aws_iam_policy.remediated_ci_deployer_privilege_escalation_chain.arn
}
```

### 4. `iam-self-service` — Privilege-escalation chain: iam:CreateRole + iam:CreateRole, iam:AttachRolePolicy

- **Severity:** 🔴 Critical
- **Finding type:** `privilege_escalation_chain`
- **Role ARN:** `arn:aws:iam::111122223333:role/iam-self-service`
- **Blast radius:** This permission combination lets the principal mint or rewrite an IAM role with arbitrary policies and hand it to a compute/service principal. That is a path to full account takeover — including the tokenization vault and payments KMS keys — i.e. total CDE compromise and a catastrophic PCI DSS failure, independent of how narrow any single statement looks.
- **Remediation:** Break the chain: scope iam:PassRole to the exact service-role ARNs the workload must pass (never '*') and add an iam:PassedToService condition; remove iam:CreateRole / iam:AttachRolePolicy / iam:PutRolePolicy unless this is a provisioning role, in which case gate it behind a permission boundary that the created roles must inherit.

<details><summary>Evidence</summary>

```json
{
  "chain": "iam:CreateRole + iam:CreateRole, iam:AttachRolePolicy",
  "companions": [
    "iam:CreateRole",
    "iam:AttachRolePolicy"
  ]
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "iam:PassRole"
  ],
  "Resource": [
    "arn:aws:iam::ACCOUNT:role/service-role/specific-task-role"
  ],
  "Condition": {
    "StringEquals": {
      "iam:PassedToService": "ecs-tasks.amazonaws.com"
    }
  }
}
```

**Terraform (ready for PR):**

```hcl
resource "aws_iam_policy" "remediated_iam_self_service_privilege_escalation_chain" {
  name        = "yuno-remediated-iam_self_service"
  description = "Least-privilege policy — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["iam:PassRole"]
        Resource = ["arn:aws:iam::ACCOUNT:role/service-role/specific-task-role"]
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "ecs-tasks.amazonaws.com"
          }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "remediated_iam_self_service_privilege_escalation_chain" {
  role       = "iam-self-service"  # replace with your tf resource reference
  policy_arn = aws_iam_policy.remediated_iam_self_service_privilege_escalation_chain.arn
}
```

### 5. `legacy-cron` — Trust policy allows assumption by ANY AWS principal

- **Severity:** 🔴 Critical
- **Finding type:** `insecure_trust_policy`
- **Role ARN:** `arn:aws:iam::111122223333:role/legacy-cron`
- **Blast radius:** Any AWS account on earth can assume this role and inherit all of its permissions. In a payments context this is a direct path into the CDE and an immediate PCI DSS Req. 7/8 failure.
- **Remediation:** Replace the broad principal with the specific role ARN(s) that legitimately assume this role, and fence the trust with sts:ExternalId and/or aws:PrincipalOrgID so only your organization's known callers qualify.

<details><summary>Evidence</summary>

```json
{
  "principal": "*",
  "condition": {}
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::TRUSTED_ACCOUNT:role/specific-caller-role"
  },
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": {
      "sts:ExternalId": "REPLACE_WITH_SHARED_SECRET",
      "aws:PrincipalOrgID": "o-REPLACE_WITH_ORG_ID"
    }
  }
}
```

**Terraform (ready for PR):**

```hcl
# Note: Updates the trust policy of existing role 'legacy-cron'.
# Bring it under Terraform management first:
#   terraform import aws_iam_role.legacy_cron legacy-cron

resource "aws_iam_role" "legacy_cron" {
  name = "legacy-cron"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::TRUSTED_ACCOUNT:role/specific-caller-role"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = "REPLACE_WITH_SHARED_SECRET"
            "aws:PrincipalOrgID" = "o-REPLACE_WITH_ORG_ID"
          }
        }
      },
    ]
  })

  lifecycle {
    ignore_changes = [description, path, tags]
  }
}
```

### 6. `payments-kms-admin` — Production payment asset access: Payments KMS keys

- **Severity:** 🔴 Critical
- **Finding type:** `pci_sensitive_data_access`
- **Role ARN:** `arn:aws:iam::111122223333:role/payments-kms-admin`
- **Blast radius:** Controls the KMS keys that encrypt cardholder data at rest. Decrypt/Encrypt access here means an attacker can read or forge encrypted PANs, defeating PCI DSS Req. 3.5/3.6 key-management controls.
- **Remediation:** Replace the wildcard/broad statement with a least-privilege block that (1) names only the exact secret/key ARNs the service needs, (2) drops write actions unless operationally required, and (3) adds an aws:SourceVpc (or aws:SourceVpce) guardrail so the credential is only usable from inside the production CDE network. Note: Replace the generic KMS key wildcard with your specific Key UUID ARNs during deployment, as IAM identity policies do not natively resolve wildcards on KMS alias strings for cryptographic operations.

<details><summary>Evidence</summary>

```json
{
  "actions": [
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:GenerateDataKey",
    "kms:ReEncryptFrom"
  ],
  "resources": [
    "arn:aws:kms:us-east-1:111122223333:alias/payments-settlement"
  ],
  "source_type": "inline",
  "source_name": "kms-payments-admin"
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:GenerateDataKey",
    "kms:ReEncryptFrom"
  ],
  "Resource": [
    "arn:aws:kms:*:*:key/*"
  ],
  "Condition": {
    "StringEquals": {
      "aws:SourceVpc": "vpc-REPLACE_WITH_PROD_VPC"
    }
  }
}
```

**Terraform (ready for PR):**

```hcl
resource "aws_iam_policy" "remediated_payments_kms_admin_pci_sensitive_data_access" {
  name        = "yuno-remediated-payments_kms_admin"
  description = "Least-privilege policy — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:ReEncryptFrom"]
        Resource = ["arn:aws:kms:*:*:key/*"]
        Condition = {
          StringEquals = {
            "aws:SourceVpc" = "vpc-REPLACE_WITH_PROD_VPC"
          }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "remediated_payments_kms_admin_pci_sensitive_data_access" {
  role       = "payments-kms-admin"  # replace with your tf resource reference
  policy_arn = aws_iam_policy.remediated_payments_kms_admin_pci_sensitive_data_access.arn
}
```

### 7. `tokenization-service` — Production payment asset access: Tokenization vault secrets (Secrets Manager)

- **Severity:** 🔴 Critical
- **Finding type:** `pci_sensitive_data_access`
- **Role ARN:** `arn:aws:iam::111122223333:role/tokenization-service`
- **Blast radius:** Grants reach into the tokenization vault that maps tokens to PANs. Compromise enables detokenization of cardholder data — a reportable PCI DSS Req. 3.4 breach and effectively a full CDE compromise.
- **Remediation:** Replace the wildcard/broad statement with a least-privilege block that (1) names only the exact secret/key ARNs the service needs, (2) drops write actions unless operationally required, and (3) adds an aws:SourceVpc (or aws:SourceVpce) guardrail so the credential is only usable from inside the production CDE network.

<details><summary>Evidence</summary>

```json
{
  "actions": [
    "secretsmanager:*"
  ],
  "resources": [
    "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/tokenization/*"
  ],
  "source_type": "inline",
  "source_name": "tokenization-vault-full"
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:*"
  ],
  "Resource": [
    "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*"
  ],
  "Condition": {
    "StringEquals": {
      "aws:SourceVpc": "vpc-REPLACE_WITH_PROD_VPC"
    }
  }
}
```

**Terraform (ready for PR):**

```hcl
resource "aws_iam_policy" "remediated_tokenization_service_pci_sensitive_data_access" {
  name        = "yuno-remediated-tokenization_service"
  description = "Least-privilege policy — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:*"]
        Resource = ["arn:aws:secretsmanager:*:*:secret:prod/tokenization/*"]
        Condition = {
          StringEquals = {
            "aws:SourceVpc" = "vpc-REPLACE_WITH_PROD_VPC"
          }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "remediated_tokenization_service_pci_sensitive_data_access" {
  role       = "tokenization-service"  # replace with your tf resource reference
  policy_arn = aws_iam_policy.remediated_tokenization_service_pci_sensitive_data_access.arn
}
```

### 8. `cross-region-replicator` — Production payment asset access: Payments KMS keys

- **Severity:** 🟠 High _(base Critical, mitigated)_
- **Finding type:** `pci_sensitive_data_access`
- **Role ARN:** `arn:aws:iam::111122223333:role/cross-region-replicator`
- **Mitigations applied:** `condition_keys:aws:SourceIp`
- **Blast radius:** Controls the KMS keys that encrypt cardholder data at rest. Decrypt/Encrypt access here means an attacker can read or forge encrypted PANs, defeating PCI DSS Req. 3.5/3.6 key-management controls.
- **Remediation:** Replace the wildcard/broad statement with a least-privilege block that (1) names only the exact secret/key ARNs the service needs, (2) drops write actions unless operationally required, and (3) adds an aws:SourceVpc (or aws:SourceVpce) guardrail so the credential is only usable from inside the production CDE network. Note: Replace the generic KMS key wildcard with your specific Key UUID ARNs during deployment, as IAM identity policies do not natively resolve wildcards on KMS alias strings for cryptographic operations.

<details><summary>Evidence</summary>

```json
{
  "actions": [
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:GenerateDataKey"
  ],
  "resources": [
    "arn:aws:kms:us-west-2:111122223333:alias/payments-replica"
  ],
  "source_type": "inline",
  "source_name": "kms-replication-fenced"
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:GenerateDataKey"
  ],
  "Resource": [
    "arn:aws:kms:*:*:key/*"
  ],
  "Condition": {
    "StringEquals": {
      "aws:SourceVpc": "vpc-REPLACE_WITH_PROD_VPC"
    }
  }
}
```

**Terraform (ready for PR):**

```hcl
resource "aws_iam_policy" "remediated_cross_region_replicator_pci_sensitive_data_access" {
  name        = "yuno-remediated-cross_region_replicator"
  description = "Least-privilege policy — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"]
        Resource = ["arn:aws:kms:*:*:key/*"]
        Condition = {
          StringEquals = {
            "aws:SourceVpc" = "vpc-REPLACE_WITH_PROD_VPC"
          }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "remediated_cross_region_replicator_pci_sensitive_data_access" {
  role       = "cross-region-replicator"  # replace with your tf resource reference
  policy_arn = aws_iam_policy.remediated_cross_region_replicator_pci_sensitive_data_access.arn
}
```

### 9. `external-analytics-bridge` — Unconditioned cross-account root trust to 999988887777

- **Severity:** 🟠 High
- **Finding type:** `insecure_trust_policy`
- **Role ARN:** `arn:aws:iam::111122223333:role/external-analytics-bridge`
- **Blast radius:** Every principal in external account 999988887777 can assume this role. Without an sts:ExternalId / aws:PrincipalOrgID fence this is exploitable via the confused-deputy pattern, exposing whatever payment resources the role can reach.
- **Remediation:** Replace the broad principal with the specific role ARN(s) that legitimately assume this role, and fence the trust with sts:ExternalId and/or aws:PrincipalOrgID so only your organization's known callers qualify.

<details><summary>Evidence</summary>

```json
{
  "principal": {
    "AWS": "arn:aws:iam::999988887777:root"
  },
  "condition": {}
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::TRUSTED_ACCOUNT:role/specific-caller-role"
  },
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": {
      "sts:ExternalId": "REPLACE_WITH_SHARED_SECRET",
      "aws:PrincipalOrgID": "o-REPLACE_WITH_ORG_ID"
    }
  }
}
```

**Terraform (ready for PR):**

```hcl
# Note: Updates the trust policy of existing role 'external-analytics-bridge'.
# Bring it under Terraform management first:
#   terraform import aws_iam_role.external_analytics_bridge external-analytics-bridge

resource "aws_iam_role" "external_analytics_bridge" {
  name = "external-analytics-bridge"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::TRUSTED_ACCOUNT:role/specific-caller-role"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = "REPLACE_WITH_SHARED_SECRET"
            "aws:PrincipalOrgID" = "o-REPLACE_WITH_ORG_ID"
          }
        }
      },
    ]
  })

  lifecycle {
    ignore_changes = [description, path, tags]
  }
}
```

### 10. `refund-processor` — Production payment asset access: Provider credentials (Secrets Manager)

- **Severity:** 🟠 High
- **Finding type:** `pci_sensitive_data_access`
- **Role ARN:** `arn:aws:iam::111122223333:role/refund-processor`
- **Blast radius:** Exposes live acquirer / PSP API credentials. An attacker could initiate or reroute settlements on behalf of the gateway, breaching PCI DSS Req. 3 (protection of stored credentials) and Req. 7 (least privilege on cardholder-data systems).
- **Remediation:** Replace the wildcard/broad statement with a least-privilege block that (1) names only the exact secret/key ARNs the service needs, (2) drops write actions unless operationally required, and (3) adds an aws:SourceVpc (or aws:SourceVpce) guardrail so the credential is only usable from inside the production CDE network.

<details><summary>Evidence</summary>

```json
{
  "actions": [
    "secretsmanager:GetSecretValue"
  ],
  "resources": [
    "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/providers/refunds-gateway-AbCdEf"
  ],
  "source_type": "inline",
  "source_name": "refund-provider-read"
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:GetSecretValue"
  ],
  "Resource": [
    "arn:aws:secretsmanager:*:*:secret:prod/providers/*"
  ],
  "Condition": {
    "StringEquals": {
      "aws:SourceVpc": "vpc-REPLACE_WITH_PROD_VPC"
    }
  }
}
```

**Terraform (ready for PR):**

```hcl
resource "aws_iam_policy" "remediated_refund_processor_pci_sensitive_data_access" {
  name        = "yuno-remediated-refund_processor"
  description = "Least-privilege policy — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
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

resource "aws_iam_role_policy_attachment" "remediated_refund_processor_pci_sensitive_data_access" {
  role       = "refund-processor"  # replace with your tf resource reference
  policy_arn = aws_iam_policy.remediated_refund_processor_pci_sensitive_data_access.arn
}
```

### 11. `token-vault-rotation` — Production payment asset access: Tokenization vault secrets (Secrets Manager)

- **Severity:** 🟠 High _(base Critical, mitigated)_
- **Finding type:** `pci_sensitive_data_access`
- **Role ARN:** `arn:aws:iam::111122223333:role/token-vault-rotation`
- **Mitigations applied:** `condition_keys:aws:SourceVpc`
- **Blast radius:** Grants reach into the tokenization vault that maps tokens to PANs. Compromise enables detokenization of cardholder data — a reportable PCI DSS Req. 3.4 breach and effectively a full CDE compromise.
- **Remediation:** Replace the wildcard/broad statement with a least-privilege block that (1) names only the exact secret/key ARNs the service needs, (2) drops write actions unless operationally required, and (3) adds an aws:SourceVpc (or aws:SourceVpce) guardrail so the credential is only usable from inside the production CDE network.

<details><summary>Evidence</summary>

```json
{
  "actions": [
    "secretsmanager:GetSecretValue",
    "secretsmanager:PutSecretValue"
  ],
  "resources": [
    "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/tokenization/*"
  ],
  "source_type": "inline",
  "source_name": "vault-rotate-fenced"
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:GetSecretValue",
    "secretsmanager:PutSecretValue"
  ],
  "Resource": [
    "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*"
  ],
  "Condition": {
    "StringEquals": {
      "aws:SourceVpc": "vpc-REPLACE_WITH_PROD_VPC"
    }
  }
}
```

**Terraform (ready for PR):**

```hcl
resource "aws_iam_policy" "remediated_token_vault_rotation_pci_sensitive_data_access" {
  name        = "yuno-remediated-token_vault_rotation"
  description = "Least-privilege policy — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"]
        Resource = ["arn:aws:secretsmanager:*:*:secret:prod/tokenization/*"]
        Condition = {
          StringEquals = {
            "aws:SourceVpc" = "vpc-REPLACE_WITH_PROD_VPC"
          }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "remediated_token_vault_rotation_pci_sensitive_data_access" {
  role       = "token-vault-rotation"  # replace with your tf resource reference
  policy_arn = aws_iam_policy.remediated_token_vault_rotation_pci_sensitive_data_access.arn
}
```

### 12. `break-glass-admin` — PCI-scope role has no permission boundary

- **Severity:** 🟡 Medium
- **Finding type:** `missing_permission_boundary`
- **Role ARN:** `arn:aws:iam::111122223333:role/break-glass-admin`
- **Blast radius:** Without a permission boundary, this role's maximum effective permissions are uncapped. Any future inline or managed policy attachment — deliberate or accidental — becomes effective immediately. For a role that already touches cardholder data (Secrets Manager or KMS), this means a single misconfigured attachment could silently promote the role to full-CDE access, violating PCI DSS Req. 7 (least-privilege enforcement) without any access-control review catching it.
- **Remediation:** Attach a permission boundary that allows only the service-level API calls this role legitimately needs. Even a coarse boundary (read-specific secrets + KMS decrypt) is significantly safer than none. Use 'aws iam put-role-permissions-boundary' or the Terraform block below. The boundary should be maintained by a separate team or automation pipeline from the role's policies.

<details><summary>Evidence</summary>

```json
{
  "pci_statements_count": 1,
  "sample_actions": [],
  "sample_resources": [
    [
      "*"
    ]
  ]
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:GetSecretValue"
  ],
  "Resource": [
    "arn:aws:secretsmanager:*:*:secret:prod/providers/*",
    "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*",
    "arn:aws:kms:*:*:key/*"
  ]
}
```

**Terraform (ready for PR):**

```hcl
# Attaches a permissions boundary — caps maximum effective permissions.
# Step 1: import the existing role (run once):
#   terraform import aws_iam_role.break_glass_admin break-glass-admin

resource "aws_iam_policy" "boundary_break_glass_admin" {
  name        = "yuno-boundary-break_glass_admin"
  description = "Permission boundary — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = [
          "arn:aws:secretsmanager:*:*:secret:prod/providers/*",
          "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*",
          "arn:aws:kms:*:*:key/*",
        ]
      },
    ]
  })
}

resource "aws_iam_role" "break_glass_admin" {
  name                 = "break-glass-admin"
  permissions_boundary = aws_iam_policy.boundary_break_glass_admin.arn

  lifecycle {
    ignore_changes = [assume_role_policy, inline_policy, description, path, tags]
  }
}
```

### 13. `checkout-router` — PCI-scope role has no permission boundary

- **Severity:** 🟡 Medium
- **Finding type:** `missing_permission_boundary`
- **Role ARN:** `arn:aws:iam::111122223333:role/checkout-router`
- **Blast radius:** Without a permission boundary, this role's maximum effective permissions are uncapped. Any future inline or managed policy attachment — deliberate or accidental — becomes effective immediately. For a role that already touches cardholder data (Secrets Manager or KMS), this means a single misconfigured attachment could silently promote the role to full-CDE access, violating PCI DSS Req. 7 (least-privilege enforcement) without any access-control review catching it.
- **Remediation:** Attach a permission boundary that allows only the service-level API calls this role legitimately needs. Even a coarse boundary (read-specific secrets + KMS decrypt) is significantly safer than none. Use 'aws iam put-role-permissions-boundary' or the Terraform block below. The boundary should be maintained by a separate team or automation pipeline from the role's policies.

<details><summary>Evidence</summary>

```json
{
  "pci_statements_count": 1,
  "sample_actions": [
    "secretsmanager:GetSecretValue",
    "secretsmanager:DescribeSecret"
  ],
  "sample_resources": [
    [
      "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/providers/*"
    ]
  ]
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:GetSecretValue",
    "secretsmanager:DescribeSecret"
  ],
  "Resource": [
    "arn:aws:secretsmanager:*:*:secret:prod/providers/*"
  ]
}
```

**Terraform (ready for PR):**

```hcl
# Attaches a permissions boundary — caps maximum effective permissions.
# Step 1: import the existing role (run once):
#   terraform import aws_iam_role.checkout_router checkout-router

resource "aws_iam_policy" "boundary_checkout_router" {
  name        = "yuno-boundary-checkout_router"
  description = "Permission boundary — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = ["arn:aws:secretsmanager:*:*:secret:prod/providers/*"]
      },
    ]
  })
}

resource "aws_iam_role" "checkout_router" {
  name                 = "checkout-router"
  permissions_boundary = aws_iam_policy.boundary_checkout_router.arn

  lifecycle {
    ignore_changes = [assume_role_policy, inline_policy, description, path, tags]
  }
}
```

### 14. `checkout-router` — Production payment asset access: Provider credentials (Secrets Manager)

- **Severity:** 🟡 Medium _(base High, mitigated)_
- **Finding type:** `pci_sensitive_data_access`
- **Role ARN:** `arn:aws:iam::111122223333:role/checkout-router`
- **Mitigations applied:** `condition_keys:aws:SourceVpc`
- **Blast radius:** Exposes live acquirer / PSP API credentials. An attacker could initiate or reroute settlements on behalf of the gateway, breaching PCI DSS Req. 3 (protection of stored credentials) and Req. 7 (least privilege on cardholder-data systems).
- **Remediation:** Replace the wildcard/broad statement with a least-privilege block that (1) names only the exact secret/key ARNs the service needs, (2) drops write actions unless operationally required, and (3) adds an aws:SourceVpc (or aws:SourceVpce) guardrail so the credential is only usable from inside the production CDE network.

<details><summary>Evidence</summary>

```json
{
  "actions": [
    "secretsmanager:GetSecretValue",
    "secretsmanager:DescribeSecret"
  ],
  "resources": [
    "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/providers/*"
  ],
  "source_type": "inline",
  "source_name": "checkout-provider-read"
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:GetSecretValue",
    "secretsmanager:DescribeSecret"
  ],
  "Resource": [
    "arn:aws:secretsmanager:*:*:secret:prod/providers/*"
  ],
  "Condition": {
    "StringEquals": {
      "aws:SourceVpc": "vpc-REPLACE_WITH_PROD_VPC"
    }
  }
}
```

**Terraform (ready for PR):**

```hcl
resource "aws_iam_policy" "remediated_checkout_router_pci_sensitive_data_access" {
  name        = "yuno-remediated-checkout_router"
  description = "Least-privilege policy — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
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

### 15. `cross-region-replicator` — PCI-scope role has no permission boundary

- **Severity:** 🟡 Medium
- **Finding type:** `missing_permission_boundary`
- **Role ARN:** `arn:aws:iam::111122223333:role/cross-region-replicator`
- **Blast radius:** Without a permission boundary, this role's maximum effective permissions are uncapped. Any future inline or managed policy attachment — deliberate or accidental — becomes effective immediately. For a role that already touches cardholder data (Secrets Manager or KMS), this means a single misconfigured attachment could silently promote the role to full-CDE access, violating PCI DSS Req. 7 (least-privilege enforcement) without any access-control review catching it.
- **Remediation:** Attach a permission boundary that allows only the service-level API calls this role legitimately needs. Even a coarse boundary (read-specific secrets + KMS decrypt) is significantly safer than none. Use 'aws iam put-role-permissions-boundary' or the Terraform block below. The boundary should be maintained by a separate team or automation pipeline from the role's policies.

<details><summary>Evidence</summary>

```json
{
  "pci_statements_count": 1,
  "sample_actions": [
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:GenerateDataKey"
  ],
  "sample_resources": [
    [
      "arn:aws:kms:us-west-2:111122223333:alias/payments-replica"
    ]
  ]
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:GenerateDataKey"
  ],
  "Resource": [
    "arn:aws:kms:*:*:key/*"
  ]
}
```

**Terraform (ready for PR):**

```hcl
# Attaches a permissions boundary — caps maximum effective permissions.
# Step 1: import the existing role (run once):
#   terraform import aws_iam_role.cross_region_replicator cross-region-replicator

resource "aws_iam_policy" "boundary_cross_region_replicator" {
  name        = "yuno-boundary-cross_region_replicator"
  description = "Permission boundary — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"]
        Resource = ["arn:aws:kms:*:*:key/*"]
      },
    ]
  })
}

resource "aws_iam_role" "cross_region_replicator" {
  name                 = "cross-region-replicator"
  permissions_boundary = aws_iam_policy.boundary_cross_region_replicator.arn

  lifecycle {
    ignore_changes = [assume_role_policy, inline_policy, description, path, tags]
  }
}
```

### 16. `data-warehouse-sync` — PCI-scope role has no permission boundary

- **Severity:** 🟡 Medium
- **Finding type:** `missing_permission_boundary`
- **Role ARN:** `arn:aws:iam::111122223333:role/data-warehouse-sync`
- **Blast radius:** Without a permission boundary, this role's maximum effective permissions are uncapped. Any future inline or managed policy attachment — deliberate or accidental — becomes effective immediately. For a role that already touches cardholder data (Secrets Manager or KMS), this means a single misconfigured attachment could silently promote the role to full-CDE access, violating PCI DSS Req. 7 (least-privilege enforcement) without any access-control review catching it.
- **Remediation:** Attach a permission boundary that allows only the service-level API calls this role legitimately needs. Even a coarse boundary (read-specific secrets + KMS decrypt) is significantly safer than none. Use 'aws iam put-role-permissions-boundary' or the Terraform block below. The boundary should be maintained by a separate team or automation pipeline from the role's policies.

<details><summary>Evidence</summary>

```json
{
  "pci_statements_count": 1,
  "sample_actions": [
    "secretsmanager:*",
    "kms:Decrypt",
    "kms:GenerateDataKey"
  ],
  "sample_resources": [
    [
      "*"
    ]
  ]
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:*",
    "kms:Decrypt",
    "kms:GenerateDataKey"
  ],
  "Resource": [
    "arn:aws:secretsmanager:*:*:secret:prod/providers/*",
    "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*",
    "arn:aws:kms:*:*:key/*"
  ]
}
```

**Terraform (ready for PR):**

```hcl
# Attaches a permissions boundary — caps maximum effective permissions.
# Step 1: import the existing role (run once):
#   terraform import aws_iam_role.data_warehouse_sync data-warehouse-sync

resource "aws_iam_policy" "boundary_data_warehouse_sync" {
  name        = "yuno-boundary-data_warehouse_sync"
  description = "Permission boundary — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:*", "kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [
          "arn:aws:secretsmanager:*:*:secret:prod/providers/*",
          "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*",
          "arn:aws:kms:*:*:key/*",
        ]
      },
    ]
  })
}

resource "aws_iam_role" "data_warehouse_sync" {
  name                 = "data-warehouse-sync"
  permissions_boundary = aws_iam_policy.boundary_data_warehouse_sync.arn

  lifecycle {
    ignore_changes = [assume_role_policy, inline_policy, description, path, tags]
  }
}
```

### 17. `db-migration-runner` — Production payment asset access: Provider credentials (Secrets Manager)

- **Severity:** 🟡 Medium _(base High, mitigated)_
- **Finding type:** `pci_sensitive_data_access`
- **Role ARN:** `arn:aws:iam::111122223333:role/db-migration-runner`
- **Mitigations applied:** `permission_boundary_present:arn:aws:iam::111122223333:policy/OpaqueBoundaryNotExported`
- **Blast radius:** Exposes live acquirer / PSP API credentials. An attacker could initiate or reroute settlements on behalf of the gateway, breaching PCI DSS Req. 3 (protection of stored credentials) and Req. 7 (least privilege on cardholder-data systems).
- **Remediation:** Replace the wildcard/broad statement with a least-privilege block that (1) names only the exact secret/key ARNs the service needs, (2) drops write actions unless operationally required, and (3) adds an aws:SourceVpc (or aws:SourceVpce) guardrail so the credential is only usable from inside the production CDE network.

<details><summary>Evidence</summary>

```json
{
  "actions": [
    "secretsmanager:GetSecretValue",
    "secretsmanager:DescribeSecret"
  ],
  "resources": [
    "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/providers/db-master-*"
  ],
  "source_type": "inline",
  "source_name": "db-secret-read"
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:GetSecretValue",
    "secretsmanager:DescribeSecret"
  ],
  "Resource": [
    "arn:aws:secretsmanager:*:*:secret:prod/providers/*"
  ],
  "Condition": {
    "StringEquals": {
      "aws:SourceVpc": "vpc-REPLACE_WITH_PROD_VPC"
    }
  }
}
```

**Terraform (ready for PR):**

```hcl
resource "aws_iam_policy" "remediated_db_migration_runner_pci_sensitive_data_access" {
  name        = "yuno-remediated-db_migration_runner"
  description = "Least-privilege policy — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
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

resource "aws_iam_role_policy_attachment" "remediated_db_migration_runner_pci_sensitive_data_access" {
  role       = "db-migration-runner"  # replace with your tf resource reference
  policy_arn = aws_iam_policy.remediated_db_migration_runner_pci_sensitive_data_access.arn
}
```

### 18. `fraud-scoring-batch` — PCI-scope role has no permission boundary

- **Severity:** 🟡 Medium
- **Finding type:** `missing_permission_boundary`
- **Role ARN:** `arn:aws:iam::111122223333:role/fraud-scoring-batch`
- **Blast radius:** Without a permission boundary, this role's maximum effective permissions are uncapped. Any future inline or managed policy attachment — deliberate or accidental — becomes effective immediately. For a role that already touches cardholder data (Secrets Manager or KMS), this means a single misconfigured attachment could silently promote the role to full-CDE access, violating PCI DSS Req. 7 (least-privilege enforcement) without any access-control review catching it.
- **Remediation:** Attach a permission boundary that allows only the service-level API calls this role legitimately needs. Even a coarse boundary (read-specific secrets + KMS decrypt) is significantly safer than none. Use 'aws iam put-role-permissions-boundary' or the Terraform block below. The boundary should be maintained by a separate team or automation pipeline from the role's policies.

<details><summary>Evidence</summary>

```json
{
  "pci_statements_count": 1,
  "sample_actions": [
    "secretsmanager:*",
    "kms:Decrypt",
    "kms:GenerateDataKey"
  ],
  "sample_resources": [
    [
      "*"
    ]
  ]
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:*",
    "kms:Decrypt",
    "kms:GenerateDataKey"
  ],
  "Resource": [
    "arn:aws:secretsmanager:*:*:secret:prod/providers/*",
    "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*",
    "arn:aws:kms:*:*:key/*"
  ]
}
```

**Terraform (ready for PR):**

```hcl
# Attaches a permissions boundary — caps maximum effective permissions.
# Step 1: import the existing role (run once):
#   terraform import aws_iam_role.fraud_scoring_batch fraud-scoring-batch

resource "aws_iam_policy" "boundary_fraud_scoring_batch" {
  name        = "yuno-boundary-fraud_scoring_batch"
  description = "Permission boundary — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:*", "kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [
          "arn:aws:secretsmanager:*:*:secret:prod/providers/*",
          "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*",
          "arn:aws:kms:*:*:key/*",
        ]
      },
    ]
  })
}

resource "aws_iam_role" "fraud_scoring_batch" {
  name                 = "fraud-scoring-batch"
  permissions_boundary = aws_iam_policy.boundary_fraud_scoring_batch.arn

  lifecycle {
    ignore_changes = [assume_role_policy, inline_policy, description, path, tags]
  }
}
```

### 19. `kms-rotation-lambda` — Production payment asset access: Payments KMS keys

- **Severity:** 🟡 Medium _(base Critical, mitigated)_
- **Finding type:** `pci_sensitive_data_access`
- **Role ARN:** `arn:aws:iam::111122223333:role/kms-rotation-lambda`
- **Mitigations applied:** `permission_boundary_caps:arn:aws:iam::111122223333:policy/ProdNetworkBoundary`
- **Blast radius:** Controls the KMS keys that encrypt cardholder data at rest. Decrypt/Encrypt access here means an attacker can read or forge encrypted PANs, defeating PCI DSS Req. 3.5/3.6 key-management controls.
- **Remediation:** Replace the wildcard/broad statement with a least-privilege block that (1) names only the exact secret/key ARNs the service needs, (2) drops write actions unless operationally required, and (3) adds an aws:SourceVpc (or aws:SourceVpce) guardrail so the credential is only usable from inside the production CDE network. Note: Replace the generic KMS key wildcard with your specific Key UUID ARNs during deployment, as IAM identity policies do not natively resolve wildcards on KMS alias strings for cryptographic operations.

<details><summary>Evidence</summary>

```json
{
  "actions": [
    "kms:*"
  ],
  "resources": [
    "arn:aws:kms:us-east-1:111122223333:alias/payments-card-encryption"
  ],
  "source_type": "inline",
  "source_name": "kms-wildcard-rotation"
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "kms:*"
  ],
  "Resource": [
    "arn:aws:kms:*:*:key/*"
  ],
  "Condition": {
    "StringEquals": {
      "aws:SourceVpc": "vpc-REPLACE_WITH_PROD_VPC"
    }
  }
}
```

**Terraform (ready for PR):**

```hcl
resource "aws_iam_policy" "remediated_kms_rotation_lambda_pci_sensitive_data_access" {
  name        = "yuno-remediated-kms_rotation_lambda"
  description = "Least-privilege policy — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["kms:*"]
        Resource = ["arn:aws:kms:*:*:key/*"]
        Condition = {
          StringEquals = {
            "aws:SourceVpc" = "vpc-REPLACE_WITH_PROD_VPC"
          }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "remediated_kms_rotation_lambda_pci_sensitive_data_access" {
  role       = "kms-rotation-lambda"  # replace with your tf resource reference
  policy_arn = aws_iam_policy.remediated_kms_rotation_lambda_pci_sensitive_data_access.arn
}
```

### 20. `merchant-onboarding` — PCI-scope role has no permission boundary

- **Severity:** 🟡 Medium
- **Finding type:** `missing_permission_boundary`
- **Role ARN:** `arn:aws:iam::111122223333:role/merchant-onboarding`
- **Blast radius:** Without a permission boundary, this role's maximum effective permissions are uncapped. Any future inline or managed policy attachment — deliberate or accidental — becomes effective immediately. For a role that already touches cardholder data (Secrets Manager or KMS), this means a single misconfigured attachment could silently promote the role to full-CDE access, violating PCI DSS Req. 7 (least-privilege enforcement) without any access-control review catching it.
- **Remediation:** Attach a permission boundary that allows only the service-level API calls this role legitimately needs. Even a coarse boundary (read-specific secrets + KMS decrypt) is significantly safer than none. Use 'aws iam put-role-permissions-boundary' or the Terraform block below. The boundary should be maintained by a separate team or automation pipeline from the role's policies.

<details><summary>Evidence</summary>

```json
{
  "pci_statements_count": 1,
  "sample_actions": [
    "secretsmanager:GetSecretValue",
    "secretsmanager:DescribeSecret"
  ],
  "sample_resources": [
    [
      "*"
    ]
  ]
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:GetSecretValue",
    "secretsmanager:DescribeSecret"
  ],
  "Resource": [
    "arn:aws:secretsmanager:*:*:secret:prod/providers/*",
    "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*",
    "arn:aws:kms:*:*:key/*"
  ]
}
```

**Terraform (ready for PR):**

```hcl
# Attaches a permissions boundary — caps maximum effective permissions.
# Step 1: import the existing role (run once):
#   terraform import aws_iam_role.merchant_onboarding merchant-onboarding

resource "aws_iam_policy" "boundary_merchant_onboarding" {
  name        = "yuno-boundary-merchant_onboarding"
  description = "Permission boundary — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = [
          "arn:aws:secretsmanager:*:*:secret:prod/providers/*",
          "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*",
          "arn:aws:kms:*:*:key/*",
        ]
      },
    ]
  })
}

resource "aws_iam_role" "merchant_onboarding" {
  name                 = "merchant-onboarding"
  permissions_boundary = aws_iam_policy.boundary_merchant_onboarding.arn

  lifecycle {
    ignore_changes = [assume_role_policy, inline_policy, description, path, tags]
  }
}
```

### 21. `merchant-onboarding-service-v2` — PCI-scope role has no permission boundary

- **Severity:** 🟡 Medium
- **Finding type:** `missing_permission_boundary`
- **Role ARN:** `arn:aws:iam::111122223333:role/merchant-onboarding-service-v2`
- **Blast radius:** Without a permission boundary, this role's maximum effective permissions are uncapped. Any future inline or managed policy attachment — deliberate or accidental — becomes effective immediately. For a role that already touches cardholder data (Secrets Manager or KMS), this means a single misconfigured attachment could silently promote the role to full-CDE access, violating PCI DSS Req. 7 (least-privilege enforcement) without any access-control review catching it.
- **Remediation:** Attach a permission boundary that allows only the service-level API calls this role legitimately needs. Even a coarse boundary (read-specific secrets + KMS decrypt) is significantly safer than none. Use 'aws iam put-role-permissions-boundary' or the Terraform block below. The boundary should be maintained by a separate team or automation pipeline from the role's policies.

<details><summary>Evidence</summary>

```json
{
  "pci_statements_count": 1,
  "sample_actions": [
    "secretsmanager:GetSecretValue",
    "secretsmanager:DescribeSecret"
  ],
  "sample_resources": [
    [
      "*"
    ]
  ]
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:GetSecretValue",
    "secretsmanager:DescribeSecret"
  ],
  "Resource": [
    "arn:aws:secretsmanager:*:*:secret:prod/providers/*",
    "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*",
    "arn:aws:kms:*:*:key/*"
  ]
}
```

**Terraform (ready for PR):**

```hcl
# Attaches a permissions boundary — caps maximum effective permissions.
# Step 1: import the existing role (run once):
#   terraform import aws_iam_role.merchant_onboarding_service_v2 merchant-onboarding-service-v2

resource "aws_iam_policy" "boundary_merchant_onboarding_service_v2" {
  name        = "yuno-boundary-merchant_onboarding_service_v2"
  description = "Permission boundary — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = [
          "arn:aws:secretsmanager:*:*:secret:prod/providers/*",
          "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*",
          "arn:aws:kms:*:*:key/*",
        ]
      },
    ]
  })
}

resource "aws_iam_role" "merchant_onboarding_service_v2" {
  name                 = "merchant-onboarding-service-v2"
  permissions_boundary = aws_iam_policy.boundary_merchant_onboarding_service_v2.arn

  lifecycle {
    ignore_changes = [assume_role_policy, inline_policy, description, path, tags]
  }
}
```

### 22. `payments-kms-admin` — PCI-scope role has no permission boundary

- **Severity:** 🟡 Medium
- **Finding type:** `missing_permission_boundary`
- **Role ARN:** `arn:aws:iam::111122223333:role/payments-kms-admin`
- **Blast radius:** Without a permission boundary, this role's maximum effective permissions are uncapped. Any future inline or managed policy attachment — deliberate or accidental — becomes effective immediately. For a role that already touches cardholder data (Secrets Manager or KMS), this means a single misconfigured attachment could silently promote the role to full-CDE access, violating PCI DSS Req. 7 (least-privilege enforcement) without any access-control review catching it.
- **Remediation:** Attach a permission boundary that allows only the service-level API calls this role legitimately needs. Even a coarse boundary (read-specific secrets + KMS decrypt) is significantly safer than none. Use 'aws iam put-role-permissions-boundary' or the Terraform block below. The boundary should be maintained by a separate team or automation pipeline from the role's policies.

<details><summary>Evidence</summary>

```json
{
  "pci_statements_count": 1,
  "sample_actions": [
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:GenerateDataKey",
    "kms:ReEncryptFrom"
  ],
  "sample_resources": [
    [
      "arn:aws:kms:us-east-1:111122223333:alias/payments-settlement"
    ]
  ]
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:GenerateDataKey",
    "kms:ReEncryptFrom"
  ],
  "Resource": [
    "arn:aws:kms:*:*:key/*"
  ]
}
```

**Terraform (ready for PR):**

```hcl
# Attaches a permissions boundary — caps maximum effective permissions.
# Step 1: import the existing role (run once):
#   terraform import aws_iam_role.payments_kms_admin payments-kms-admin

resource "aws_iam_policy" "boundary_payments_kms_admin" {
  name        = "yuno-boundary-payments_kms_admin"
  description = "Permission boundary — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:ReEncryptFrom"]
        Resource = ["arn:aws:kms:*:*:key/*"]
      },
    ]
  })
}

resource "aws_iam_role" "payments_kms_admin" {
  name                 = "payments-kms-admin"
  permissions_boundary = aws_iam_policy.boundary_payments_kms_admin.arn

  lifecycle {
    ignore_changes = [assume_role_policy, inline_policy, description, path, tags]
  }
}
```

### 23. `refund-processor` — PCI-scope role has no permission boundary

- **Severity:** 🟡 Medium
- **Finding type:** `missing_permission_boundary`
- **Role ARN:** `arn:aws:iam::111122223333:role/refund-processor`
- **Blast radius:** Without a permission boundary, this role's maximum effective permissions are uncapped. Any future inline or managed policy attachment — deliberate or accidental — becomes effective immediately. For a role that already touches cardholder data (Secrets Manager or KMS), this means a single misconfigured attachment could silently promote the role to full-CDE access, violating PCI DSS Req. 7 (least-privilege enforcement) without any access-control review catching it.
- **Remediation:** Attach a permission boundary that allows only the service-level API calls this role legitimately needs. Even a coarse boundary (read-specific secrets + KMS decrypt) is significantly safer than none. Use 'aws iam put-role-permissions-boundary' or the Terraform block below. The boundary should be maintained by a separate team or automation pipeline from the role's policies.

<details><summary>Evidence</summary>

```json
{
  "pci_statements_count": 1,
  "sample_actions": [
    "secretsmanager:GetSecretValue"
  ],
  "sample_resources": [
    [
      "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/providers/refunds-gateway-AbCdEf"
    ]
  ]
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:GetSecretValue"
  ],
  "Resource": [
    "arn:aws:secretsmanager:*:*:secret:prod/providers/*"
  ]
}
```

**Terraform (ready for PR):**

```hcl
# Attaches a permissions boundary — caps maximum effective permissions.
# Step 1: import the existing role (run once):
#   terraform import aws_iam_role.refund_processor refund-processor

resource "aws_iam_policy" "boundary_refund_processor" {
  name        = "yuno-boundary-refund_processor"
  description = "Permission boundary — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = ["arn:aws:secretsmanager:*:*:secret:prod/providers/*"]
      },
    ]
  })
}

resource "aws_iam_role" "refund_processor" {
  name                 = "refund-processor"
  permissions_boundary = aws_iam_policy.boundary_refund_processor.arn

  lifecycle {
    ignore_changes = [assume_role_policy, inline_policy, description, path, tags]
  }
}
```

### 24. `reporting-etl` — PCI-scope role has no permission boundary

- **Severity:** 🟡 Medium
- **Finding type:** `missing_permission_boundary`
- **Role ARN:** `arn:aws:iam::111122223333:role/reporting-etl`
- **Blast radius:** Without a permission boundary, this role's maximum effective permissions are uncapped. Any future inline or managed policy attachment — deliberate or accidental — becomes effective immediately. For a role that already touches cardholder data (Secrets Manager or KMS), this means a single misconfigured attachment could silently promote the role to full-CDE access, violating PCI DSS Req. 7 (least-privilege enforcement) without any access-control review catching it.
- **Remediation:** Attach a permission boundary that allows only the service-level API calls this role legitimately needs. Even a coarse boundary (read-specific secrets + KMS decrypt) is significantly safer than none. Use 'aws iam put-role-permissions-boundary' or the Terraform block below. The boundary should be maintained by a separate team or automation pipeline from the role's policies.

<details><summary>Evidence</summary>

```json
{
  "pci_statements_count": 1,
  "sample_actions": [
    "secretsmanager:*",
    "kms:Decrypt",
    "kms:GenerateDataKey"
  ],
  "sample_resources": [
    [
      "*"
    ]
  ]
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:*",
    "kms:Decrypt",
    "kms:GenerateDataKey"
  ],
  "Resource": [
    "arn:aws:secretsmanager:*:*:secret:prod/providers/*",
    "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*",
    "arn:aws:kms:*:*:key/*"
  ]
}
```

**Terraform (ready for PR):**

```hcl
# Attaches a permissions boundary — caps maximum effective permissions.
# Step 1: import the existing role (run once):
#   terraform import aws_iam_role.reporting_etl reporting-etl

resource "aws_iam_policy" "boundary_reporting_etl" {
  name        = "yuno-boundary-reporting_etl"
  description = "Permission boundary — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:*", "kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [
          "arn:aws:secretsmanager:*:*:secret:prod/providers/*",
          "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*",
          "arn:aws:kms:*:*:key/*",
        ]
      },
    ]
  })
}

resource "aws_iam_role" "reporting_etl" {
  name                 = "reporting-etl"
  permissions_boundary = aws_iam_policy.boundary_reporting_etl.arn

  lifecycle {
    ignore_changes = [assume_role_policy, inline_policy, description, path, tags]
  }
}
```

### 25. `token-vault-rotation` — PCI-scope role has no permission boundary

- **Severity:** 🟡 Medium
- **Finding type:** `missing_permission_boundary`
- **Role ARN:** `arn:aws:iam::111122223333:role/token-vault-rotation`
- **Blast radius:** Without a permission boundary, this role's maximum effective permissions are uncapped. Any future inline or managed policy attachment — deliberate or accidental — becomes effective immediately. For a role that already touches cardholder data (Secrets Manager or KMS), this means a single misconfigured attachment could silently promote the role to full-CDE access, violating PCI DSS Req. 7 (least-privilege enforcement) without any access-control review catching it.
- **Remediation:** Attach a permission boundary that allows only the service-level API calls this role legitimately needs. Even a coarse boundary (read-specific secrets + KMS decrypt) is significantly safer than none. Use 'aws iam put-role-permissions-boundary' or the Terraform block below. The boundary should be maintained by a separate team or automation pipeline from the role's policies.

<details><summary>Evidence</summary>

```json
{
  "pci_statements_count": 1,
  "sample_actions": [
    "secretsmanager:GetSecretValue",
    "secretsmanager:PutSecretValue"
  ],
  "sample_resources": [
    [
      "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/tokenization/*"
    ]
  ]
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:GetSecretValue",
    "secretsmanager:PutSecretValue"
  ],
  "Resource": [
    "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*"
  ]
}
```

**Terraform (ready for PR):**

```hcl
# Attaches a permissions boundary — caps maximum effective permissions.
# Step 1: import the existing role (run once):
#   terraform import aws_iam_role.token_vault_rotation token-vault-rotation

resource "aws_iam_policy" "boundary_token_vault_rotation" {
  name        = "yuno-boundary-token_vault_rotation"
  description = "Permission boundary — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"]
        Resource = ["arn:aws:secretsmanager:*:*:secret:prod/tokenization/*"]
      },
    ]
  })
}

resource "aws_iam_role" "token_vault_rotation" {
  name                 = "token-vault-rotation"
  permissions_boundary = aws_iam_policy.boundary_token_vault_rotation.arn

  lifecycle {
    ignore_changes = [assume_role_policy, inline_policy, description, path, tags]
  }
}
```

### 26. `tokenization-service` — PCI-scope role has no permission boundary

- **Severity:** 🟡 Medium
- **Finding type:** `missing_permission_boundary`
- **Role ARN:** `arn:aws:iam::111122223333:role/tokenization-service`
- **Blast radius:** Without a permission boundary, this role's maximum effective permissions are uncapped. Any future inline or managed policy attachment — deliberate or accidental — becomes effective immediately. For a role that already touches cardholder data (Secrets Manager or KMS), this means a single misconfigured attachment could silently promote the role to full-CDE access, violating PCI DSS Req. 7 (least-privilege enforcement) without any access-control review catching it.
- **Remediation:** Attach a permission boundary that allows only the service-level API calls this role legitimately needs. Even a coarse boundary (read-specific secrets + KMS decrypt) is significantly safer than none. Use 'aws iam put-role-permissions-boundary' or the Terraform block below. The boundary should be maintained by a separate team or automation pipeline from the role's policies.

<details><summary>Evidence</summary>

```json
{
  "pci_statements_count": 1,
  "sample_actions": [
    "secretsmanager:*"
  ],
  "sample_resources": [
    [
      "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/tokenization/*"
    ]
  ]
}
```
</details>

**Least-privilege replacement:**

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:*"
  ],
  "Resource": [
    "arn:aws:secretsmanager:*:*:secret:prod/tokenization/*"
  ]
}
```

**Terraform (ready for PR):**

```hcl
# Attaches a permissions boundary — caps maximum effective permissions.
# Step 1: import the existing role (run once):
#   terraform import aws_iam_role.tokenization_service tokenization-service

resource "aws_iam_policy" "boundary_tokenization_service" {
  name        = "yuno-boundary-tokenization_service"
  description = "Permission boundary — IAM Contextual Risk Analyzer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:*"]
        Resource = ["arn:aws:secretsmanager:*:*:secret:prod/tokenization/*"]
      },
    ]
  })
}

resource "aws_iam_role" "tokenization_service" {
  name                 = "tokenization-service"
  permissions_boundary = aws_iam_policy.boundary_tokenization_service.arn

  lifecycle {
    ignore_changes = [assume_role_policy, inline_policy, description, path, tags]
  }
}
```

### 27. `dev-sandbox-tester` — Broad secret/KMS access scoped to non-production

- **Severity:** ⚪ Informational _(base Low, mitigated)_
- **Finding type:** `pci_sensitive_data_access`
- **Role ARN:** `arn:aws:iam::111122223333:role/dev-sandbox-tester`
- **Mitigations applied:** `resource_scope:non_production_only`
- **Blast radius:** Wildcard access to secrets/KMS, but every resource is a dev/staging/sandbox prefix. No cardholder data is reachable; outside the CDE and out of PCI DSS scope.
- **Remediation:** No urgent action. Optionally tighten the resource scope to the specific non-prod ARNs to keep blast radius minimal.

<details><summary>Evidence</summary>

```json
{
  "actions": [
    "secretsmanager:*"
  ],
  "resources": [
    "arn:aws:secretsmanager:us-east-1:111122223333:secret:dev/*"
  ],
  "source": "dev-secrets-playground"
}
```
</details>
