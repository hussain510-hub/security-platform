# Module 2 — Automated Compliance

> **Continuous Compliance Monitoring across AWS + Azure**
> **Status:** ✅ Complete | **Clouds:** AWS (eu-north-1) + Azure | **Standards:** GDPR · ISO 27001 · PCI-DSS · CIS · SOC2

---

## Table of Contents
- [What This Module Does](#what-this-module-does)
- [Architecture Diagram](#architecture-diagram)
- [Module 1 vs Module 2 — Key Difference](#module-1-vs-module-2--key-difference)
- [Tools Used](#tools-used)
- [Folder Structure](#folder-structure)
- [Part 1 — AWS Config](#part-1--aws-config)
- [Part 2 — Azure Policy](#part-2--azure-policy)
- [Part 3 — Cloud Custodian](#part-3--cloud-custodian)
- [Compliance Reports Generated](#compliance-reports-generated)
- [How This Feeds the Next Module](#how-this-feeds-the-next-module)

---

## What This Module Does

Module 2 transforms security from **reactive** (scan and find) to **proactive** (continuously monitor and prevent). It deploys three layers of automated compliance enforcement across AWS and Azure.

```
Module 1  =  Doctor who checks your health ONCE and writes a report
Module 2  =  Heart monitor that checks 24/7 and ALERTS automatically
```

---

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                   MODULE 2 — AUTOMATED COMPLIANCE                    │
└──────────────────────────────────────────────────────────────────────┘

                         ┌──────────────────┐
                         │   Module 1 CSVs  │  (Prowler findings — input)
                         └────────┬─────────┘
                                  │ Gap Analysis Input
            ┌─────────────────────┼─────────────────────┐
            │                     │                     │
   ┌────────▼─────────┐  ┌────────▼────────┐  ┌────────▼────────────┐
   │    AWS Config     │  │  Azure Policy   │  │  Cloud Custodian    │
   │                   │  │                 │  │                     │
   │  ┌─────────────┐  │  │ ┌─────────────┐│  │  ┌───────────────┐  │
   │  │ S3 Rules    │  │  │ │ require-tags ││  │  │ Tag Policies  │  │
   │  │ IAM Rules   │  │  │ │ (ISO27001)  ││  │  │ Encryption    │  │
   │  │ CloudTrail  │  │  │ ├─────────────┤│  │  │ Rules        │  │
   │  │ Rules       │  │  │ │ allowed-loc ││  │  └───────────────┘  │
   │  │ Encryption  │  │  │ │ (GDPR)     ││  │                     │
   │  │ Rules       │  │  │ ├─────────────┤│  │  Detects AND can   │
   │  └─────────────┘  │  │ │ require-    ││  │  auto-remediate    │
   │                   │  │ │ https-stor  ││  └──────────┬──────────┘
   │  Continuous 24/7  │  │ │ (PCI-DSS)  ││             │
   │  PASS/FAIL check  │  │ └─────────────┘│             │
   └────────┬──────────┘  └────────┬───────┘             │
            │                      │                      │
            └──────────────────────┼──────────────────────┘
                                   │
                        ┌──────────▼──────────┐
                        │   COMPLIANCE REPORTS │
                        │  gdpr-report.md      │
                        │  iso27001-report.md  │
                        │  pci-dss-report.md   │
                        │  aws-config-*.json   │
                        └─────────────────────┘
```

---

## Module 1 vs Module 2 — Key Difference

| Aspect | Module 1 | Module 2 |
|--------|---------|---------|
| Approach | Reactive | Proactive |
| Trigger | Manual scan | Continuous / automatic |
| Output | Point-in-time findings | Ongoing compliance state |
| Analogy | Security audit | Security operations |
| Tools | Prowler, ScoutSuite | AWS Config, Azure Policy, Cloud Custodian |

---

## Tools Used

| Tool | What It Does | Standard / Purpose |
|------|-------------|-------------------|
| **AWS Config** | Watches your AWS account 24/7. Every change triggers a rule check — returns PASS or FAIL | CIS, GDPR, ISO 27001, SOC2 |
| **Azure Policy** | Prevents non-compliant resources from being created in Azure — blocks violations **before** they happen | GDPR, ISO 27001, PCI-DSS |
| **Cloud Custodian** | Detects policy violations and can automatically tag or remediate them | CIS, GDPR, ISO 27001, PCI-DSS |

---

## Folder Structure

```
module2-compliance/
│
├── README.md
│
├── aws-config/
│   └── enable-config-rules.sh        ← Script that activates all AWS Config rules
│
├── azure-policy/
│   ├── require-tags-policy.json      ← ISO 27001 — enforce resource tagging
│   ├── allowed-locations-policy.json ← GDPR — restrict data to EU regions
│   ├── require-https-storage.json    ← PCI-DSS — force HTTPS on storage
│   ├── policy-assignments.json       ← Evidence: proof policies are active
│   └── deploy-azure-policies.sh      ← One-shot Azure deployment script
│
└── reports/
    ├── aws-config-compliance.json    ← Real AWS Config evaluation results
    ├── gdpr-compliance-report.md     ← GDPR gap analysis report
    ├── iso27001-compliance-report.md ← ISO 27001 gap analysis report
    └── pci-dss-compliance-report.md  ← PCI-DSS gap analysis report
```

---

## Part 1 — AWS Config

AWS Config is Amazon's built-in compliance recorder. Every time someone changes a resource in AWS, Config records it **and** checks it against your rules.

### Setup Flow

```
Step 1: Create S3 bucket         ← Config needs storage for compliance records
Step 2: Set bucket policy        ← Allow Config service to write to the bucket
Step 3: Create IAM Role          ← Give Config its own identity to access AWS
Step 4: Start Config Recorder    ← Begin recording all resource changes
Step 5: Enable Managed Rules     ← Activate pre-built compliance rules
Step 6: Run evaluation           ← Trigger immediate rule checks
```

### Key Commands

```bash
# Create storage for Config
aws s3 mb s3://security-platform-config-334960985321 --region eu-north-1

# Create IAM role for Config
aws iam create-role \
  --role-name AWSConfigRole \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"config.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

aws iam attach-role-policy \
  --role-name AWSConfigRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWS_ConfigRole

# Start the recorder
aws configservice start-configuration-recorder \
  --configuration-recorder-name default

# Enable key compliance rules
aws configservice put-config-rule \
  --config-rule '{"ConfigRuleName":"s3-bucket-public-read-prohibited","Source":{"Owner":"AWS","SourceIdentifier":"S3_BUCKET_PUBLIC_READ_PROHIBITED"}}'

aws configservice put-config-rule \
  --config-rule '{"ConfigRuleName":"mfa-enabled-for-iam-console-access","Source":{"Owner":"AWS","SourceIdentifier":"MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"}}'

# Get compliance status
aws configservice describe-compliance-by-config-rule \
  --output json > reports/aws-config-compliance.json
```

### AWS Config Rules Deployed

| Rule Name | Standard | What It Checks |
|-----------|----------|---------------|
| `s3-bucket-public-read-prohibited` | CIS / GDPR | S3 buckets must not be publicly readable |
| `mfa-enabled-for-iam-console-access` | CIS / ISO 27001 | All IAM users must have MFA |
| `cloudtrail-enabled` | SOC2 / ISO 27001 | CloudTrail must be active in all regions |
| `encrypted-volumes` | PCI-DSS | All EBS volumes must be encrypted |
| `rds-storage-encrypted` | PCI-DSS / GDPR | RDS databases must use encryption |
| `root-account-mfa-enabled` | CIS | Root account must have MFA |
| `iam-password-policy` | CIS / ISO 27001 | Password complexity rules enforced |

---

## Part 2 — Azure Policy

Azure Policy is a **preventive** control — it blocks non-compliant resources from being created in the first place.

### Policies Deployed

#### Policy 1 — Require Resource Tags (ISO 27001)
```json
{
  "displayName": "Require Environment and Owner tags",
  "policyRule": {
    "if": {
      "anyOf": [
        {"field": "tags['Environment']", "exists": "false"},
        {"field": "tags['Owner']", "exists": "false"}
      ]
    },
    "then": {"effect": "deny"}
  }
}
```

#### Policy 2 — Allowed Locations (GDPR)
Restricts resource creation to EU regions only (`northeurope`, `westeurope`):
```json
{
  "displayName": "Allowed locations — EU only (GDPR)",
  "policyRule": {
    "if": {
      "not": {"field": "location", "in": ["northeurope","westeurope","global"]}
    },
    "then": {"effect": "deny"}
  }
}
```

#### Policy 3 — Require HTTPS on Storage (PCI-DSS)
Forces all Azure Storage accounts to require HTTPS:
```json
{
  "displayName": "Storage accounts require HTTPS only (PCI-DSS)",
  "policyRule": {
    "if": {
      "allOf": [
        {"field": "type", "equals": "Microsoft.Storage/storageAccounts"},
        {"field": "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly", "equals": "false"}
      ]
    },
    "then": {"effect": "deny"}
  }
}
```

### Deployment Commands

```bash
# Get your Azure subscription ID
az account show --query id --output tsv

# Create and assign each policy
az policy definition create \
  --name "require-tags-iso27001" \
  --display-name "Require Environment and Owner tags" \
  --rules azure-policy/require-tags-policy.json

az policy assignment create \
  --name "require-tags-assignment" \
  --policy "require-tags-iso27001" \
  --scope "/subscriptions/YOUR_SUBSCRIPTION_ID"

# Verify policies are active
az policy assignment list --output json > azure-policy/policy-assignments.json
```

---

## Part 3 — Cloud Custodian

Cloud Custodian adds a **detection + remediation** layer — it can both find violations and automatically fix them.

### Example Policy — S3 Public Access Block

```yaml
policies:
  - name: s3-public-access-block
    resource: s3
    filters:
      - type: value
        key: PublicAccessBlockConfiguration.BlockPublicAcls
        value: false
    actions:
      - type: set-public-block
        BlockPublicAcls: true
```

```bash
custodian run --output-dir=custodian-output s3-public-block.yml
```

---

## Compliance Reports Generated

| Report | Standard | Key Findings |
|--------|----------|-------------|
| `gdpr-compliance-report.md` | GDPR | Data encryption status, EU region residency, access logging |
| `iso27001-compliance-report.md` | ISO 27001 | Asset tagging, access control, audit trail completeness |
| `pci-dss-compliance-report.md` | PCI-DSS | Encryption at rest, HTTPS enforcement, network segmentation |
| `aws-config-compliance.json` | Multiple | Machine-readable PASS/FAIL per Config rule |

---

## How This Feeds the Next Module

```
Module 2 Output                    →    Consumed By
─────────────────────────────────────────────────────
Compliance gap analysis reports    →    Module 3 (risk scoring context)
AWS Config PASS/FAIL data          →    Module 6 (compliance % in dashboard)
Azure Policy assignment evidence   →    Module 6 (compliance framework mapping)
```

> **Key insight for the interview:** Module 2 is the difference between a security audit (Module 1) and a security operations system. Audits happen once. Operations happen continuously. AWS Config and Azure Policy are always watching — even at 3am on a Sunday.
