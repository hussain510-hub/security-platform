# Module 2 — Automated Compliance

> **Continuous Compliance Monitoring & Regulatory Management**  
> AWS (eu-north-1) + Microsoft Azure

**Status:** ✅ Complete  
**Tools:** AWS Config · Azure Policy · Cloud Custodian  
**Standards:** GDPR · ISO 27001 · PCI-DSS · CIS · SOC 2

---

## What This Module Does

Module 2 builds on Module 1's point-in-time scans and turns them into **continuous, automated compliance monitoring**. Rather than running a scan manually, Module 2 deploys systems that watch 24/7 and enforce rules automatically.

| Module 1 | Module 2 |
|----------|----------|
| Reactive — run scans to discover problems | Proactive — systems continuously monitor and prevent violations |
| Like a doctor who checks your health once | Like a monitoring device that checks your health 24/7 |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    MODULE 2 ARCHITECTURE                             │
│                                                                      │
│   ┌────────────────────────────────────────────────────────────┐    │
│   │                       AWS SIDE                             │    │
│   │                                                            │    │
│   │   Any resource change in AWS account                       │    │
│   │              │                                             │    │
│   │              ▼                                             │    │
│   │   ┌─────────────────────────────────────┐                 │    │
│   │   │          AWS Config Recorder        │                 │    │
│   │   │  Records every change in the account│                 │    │
│   │   └──────────────┬──────────────────────┘                 │    │
│   │                  │                                         │    │
│   │         ┌────────▼────────┐                               │    │
│   │         │  Config Rules   │                               │    │
│   │         │  cloudtrail-    │                               │    │
│   │         │  enabled        │◄── CIS, ISO27001, GDPR        │    │
│   │         │  encrypted-     │◄── PCI-DSS, GDPR              │    │
│   │         │  volumes        │                               │    │
│   │         │  iam-password-  │◄── CIS, SOC2                  │    │
│   │         │  policy         │                               │    │
│   │         └────────┬────────┘                               │    │
│   │                  │ PASS / FAIL                             │    │
│   │                  ▼                                         │    │
│   │         ┌────────────────┐                                │    │
│   │         │  S3 Bucket     │                                │    │
│   │         │  (compliance   │                                │    │
│   │         │   records)     │                                │    │
│   │         └────────────────┘                                │    │
│   └────────────────────────────────────────────────────────────┘    │
│                                                                      │
│   ┌────────────────────────────────────────────────────────────┐    │
│   │                      AZURE SIDE                            │    │
│   │                                                            │    │
│   │  Any resource deployment request                           │    │
│   │              │                                             │    │
│   │              ▼                                             │    │
│   │   ┌─────────────────────────────────────┐                 │    │
│   │   │         Azure Policy Engine         │                 │    │
│   │   │  Intercepts BEFORE resource exists  │                 │    │
│   │   └──────────────┬──────────────────────┘                 │    │
│   │                  │                                         │    │
│   │    ┌─────────────┼─────────────┐                          │    │
│   │    ▼             ▼             ▼                           │    │
│   │  Require       Allowed       HTTPS                         │    │
│   │   Tags        Locations      Only                          │    │
│   │ (ISO27001)    (GDPR)       (PCI-DSS)                      │    │
│   │    │             │             │                           │    │
│   │    └─────────────┼─────────────┘                          │    │
│   │                  ▼                                         │    │
│   │         DENY (non-compliant) / ALLOW (compliant)          │    │
│   └────────────────────────────────────────────────────────────┘    │
│                                                                      │
│   ┌────────────────────────────────────────────────────────────┐    │
│   │                    REPORTS OUTPUT                          │    │
│   │    GDPR Report · ISO 27001 Report · PCI-DSS Report         │    │
│   └────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Tools Overview

| Tool | What It Does | Standard / Purpose |
|------|-------------|-------------------|
| **AWS Config** | Watches the entire AWS account 24/7. Checks if security rules are being followed and reports PASS or FAIL | CIS, GDPR, ISO 27001, SOC2 |
| **Azure Policy** | Prevents non-compliant resources from being created in Azure. Blocks violations before they happen | GDPR, ISO 27001, PCI-DSS |
| **Cloud Custodian** | Detects policy violations and can automatically tag or fix them | CIS, GDPR, ISO 27001, PCI-DSS |

---

## Folder Structure

```
module2-automated-compliance/
├── aws-config/
│   └── enable-config-rules.sh         ← Script that set up AWS Config
├── azure-policy/
│   ├── require-tags-policy.json       ← ISO27001 resource tagging policy
│   ├── allowed-locations-policy.json  ← GDPR data residency policy
│   ├── require-https-storage.json     ← PCI-DSS HTTPS enforcement policy
│   ├── policy-assignments.json        ← Proof policies are active
│   └── deploy-azure-policies.sh       ← Azure deployment script
└── reports/
    ├── aws-config-compliance.json     ← Real AWS Config compliance results
    ├── gdpr-compliance-report.md      ← GDPR gap analysis
    ├── iso27001-compliance-report.md  ← ISO 27001 gap analysis
    └── pci-dss-compliance-report.md   ← PCI-DSS gap analysis
```

---

## Part 1 — AWS Config

AWS Config is Amazon's built-in compliance checker. Think of it like a **security camera + rule checker** — every time something changes in the AWS account, Config records it AND checks if it breaks any security rules.

### Setup Steps

**Step 1 — Create S3 Bucket for Config storage**

```bash
aws s3 mb s3://security-platform-config-334960985321 \
  --region eu-north-1
```

**Step 2 — Grant AWS Config permission to write to bucket**

```bash
aws s3api put-bucket-policy \
  --bucket security-platform-config-334960985321 \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "AWSConfigBucketPermissionsCheck",
        "Effect": "Allow",
        "Principal": { "Service": "config.amazonaws.com" },
        "Action": "s3:GetBucketAcl",
        "Resource": "arn:aws:s3:::security-platform-config-334960985321"
      },
      {
        "Sid": "AWSConfigBucketDelivery",
        "Effect": "Allow",
        "Principal": { "Service": "config.amazonaws.com" },
        "Action": "s3:PutObject",
        "Resource": "arn:aws:s3:::security-platform-config-334960985321/AWSLogs/334960985321/Config/*"
      }
    ]
  }'
```

**Step 3 — Create IAM Role for AWS Config**

```bash
# Create the role
aws iam create-role \
  --role-name AWSConfigRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{ "Effect": "Allow",
      "Principal": { "Service": "config.amazonaws.com" },
      "Action": "sts:AssumeRole" }]
  }'

# Attach permissions
aws iam attach-role-policy \
  --role-name AWSConfigRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWS_ConfigRole
```

**Step 4 — Start the Recorder**

```bash
# Configure recorder
aws configservice put-configuration-recorder \
  --configuration-recorder name=default,roleARN=arn:aws:iam::334960985321:role/AWSConfigRole \
  --recording-group allSupported=true,includeGlobalResourceTypes=true \
  --region eu-north-1

# Set delivery channel
aws configservice put-delivery-channel \
  --delivery-channel name=default,s3BucketName=security-platform-config-334960985321 \
  --region eu-north-1

# Start recording
aws configservice start-configuration-recorder \
  --configuration-recorder-name default \
  --region eu-north-1
```

**Step 5 — Verify**

```bash
aws configservice describe-configuration-recorder-status --region eu-north-1
# Expected: recording: true, lastStatus: "SUCCESS"
```

### AWS Config Compliance Rules

| Rule Name | What It Checks | Standard |
|-----------|---------------|----------|
| `cloudtrail-enabled` | Is AWS activity logging turned ON? Without this there is no record of who did what in the account | CIS, ISO 27001, GDPR |
| `encrypted-volumes` | Are all EBS volumes encrypted? Unencrypted drives expose data if stolen | PCI-DSS, GDPR |
| `iam-password-policy` | Is the password policy strong enough? Weak passwords are one of the biggest security risks | CIS, SOC2 |

```bash
# Rule 1 — CloudTrail enabled
aws configservice put-config-rule \
  --config-rule '{"ConfigRuleName":"cloudtrail-enabled","Source":{"Owner":"AWS","SourceIdentifier":"CLOUD_TRAIL_ENABLED"}}' \
  --region eu-north-1

# Rule 2 — Encrypted volumes
aws configservice put-config-rule \
  --config-rule '{"ConfigRuleName":"encrypted-volumes","Source":{"Owner":"AWS","SourceIdentifier":"ENCRYPTED_VOLUMES"}}' \
  --region eu-north-1

# Rule 3 — IAM password policy
aws configservice put-config-rule \
  --config-rule '{"ConfigRuleName":"iam-password-policy","Source":{"Owner":"AWS","SourceIdentifier":"IAM_PASSWORD_POLICY"}}' \
  --region eu-north-1
```

---

## Part 2 — Azure Policy

Azure Policy operates differently from AWS Config — instead of **detecting after the fact**, Azure Policy **prevents** non-compliant resources from being created at all.

```
Developer requests resource deployment
              │
              ▼
    ┌─────────────────┐
    │  Azure Policy   │   ◄── Checks policies BEFORE resource is created
    │    Engine       │
    └────────┬────────┘
             │
    ┌────────▼────────┐        ┌─────────────────┐
    │  Non-compliant? │──YES──▶│  DENY: Resource │
    └────────┬────────┘        │  not created    │
             │ NO              └─────────────────┘
             ▼
    ┌─────────────────┐
    │ Resource created│
    │   successfully  │
    └─────────────────┘
```

### Three Azure Policies Deployed

**Policy 1 — Require Tags (`require-tags-policy.json`) — ISO 27001**

All resources must have `environment` and `owner` tags for asset management and accountability.

```json
{
  "mode": "All",
  "policyRule": {
    "if": {
      "anyOf": [
        { "field": "tags['environment']", "exists": "false" },
        { "field": "tags['owner']", "exists": "false" }
      ]
    },
    "then": { "effect": "deny" }
  }
}
```

**Policy 2 — Allowed Locations (`allowed-locations-policy.json`) — GDPR**

Resources can only be deployed in EU regions (UK South, North Europe, West Europe). This ensures GDPR data residency compliance — EU citizen data stays in the EU.

**Policy 3 — Require HTTPS Storage (`require-https-storage.json`) — PCI-DSS**

All Azure storage accounts must enforce HTTPS-only access. No unencrypted HTTP connections allowed.

### Deploying Azure Policies

```bash
# Create policy definitions
az policy definition create \
  --name require-resource-tags \
  --rules @azure-policy/require-tags-policy.json \
  --mode All

az policy definition create \
  --name allowed-locations \
  --rules @azure-policy/allowed-locations-policy.json \
  --mode All

az policy definition create \
  --name require-https-storage \
  --rules @azure-policy/require-https-storage.json \
  --mode All

# Get subscription ID
SUBSCRIPTION_ID=$(az account show --query id -o tsv)

# Assign policies to subscription
az policy assignment create \
  --name require-tags-assignment \
  --policy require-resource-tags \
  --scope /subscriptions/$SUBSCRIPTION_ID

az policy assignment create \
  --name allowed-locations-assignment \
  --policy allowed-locations \
  --scope /subscriptions/$SUBSCRIPTION_ID

az policy assignment create \
  --name require-https-assignment \
  --policy require-https-storage \
  --scope /subscriptions/$SUBSCRIPTION_ID

# Verify assignments
az policy assignment list --output table
```

### Azure Policy Compliance Status

| Policy | Standard | Effect | Status |
|--------|----------|--------|--------|
| Require Tags | ISO 27001 A.8.1 | Deny | ✅ Active |
| Allowed Locations (EU only) | GDPR Art.46 | Deny | ✅ Active |
| HTTPS-only Storage | PCI-DSS Req.4 | Deny | ✅ Active |

---

## Part 3 — Compliance Gap Analysis Reports

### GDPR Report Summary

| GDPR Article | Requirement | AWS Status | Azure Status |
|-------------|-------------|-----------|--------------|
| Art. 5(1)(f) | Data integrity and confidentiality | ❌ 60.98% failing | ✅ Policy enforced |
| Art. 25 | Data protection by design | ❌ Missing encryption | ✅ HTTPS enforced |
| Art. 32 | Security of processing | ❌ Unencrypted EBS/S3 | ✅ Location restricted |
| Art. 46 | Data residency | ❌ Not enforced in AWS | ✅ EU-only policy active |

### ISO 27001 Report Summary

| Control | Requirement | Status |
|---------|-------------|--------|
| A.9.4.2 | Secure log-on procedures | ❌ No MFA on IAM users |
| A.10.1 | Cryptographic controls | ❌ Unencrypted volumes found |
| A.12.4 | Logging and monitoring | ❌ CloudTrail not enabled |
| A.8.1.1 | Asset inventory | ✅ Enforced via Azure tagging policy |

### PCI-DSS Report Summary

| Requirement | What It Covers | Status |
|------------|---------------|--------|
| Req. 1 | Firewall configuration | ❌ SSH open to 0.0.0.0/0 |
| Req. 3 | Protect stored cardholder data | ❌ EBS volumes unencrypted |
| Req. 4 | Encrypt data in transit | ✅ Azure HTTPS policy active |
| Req. 7 | Restrict access to cardholder data | ❌ Overprivileged IAM roles |
| Req. 10 | Log and monitor all access | ❌ CloudTrail disabled |

---

## Comparison: AWS Config vs Azure Policy

| Feature | AWS Config | Azure Policy |
|---------|-----------|--------------|
| **When it acts** | After resources exist | Before resources are created |
| **Primary function** | Detect and report compliance violations | Prevent non-compliant resources |
| **Remediation** | Can trigger Lambda for auto-fix | Built-in Deny effect |
| **Scope** | Per-region rules | Subscription-wide |
| **Analogy** | CCTV camera that records violations | Security guard who blocks entry |

---

## Exam Objective Coverage

| Topic 97 Objective | How Module 2 Satisfies It |
|--------------------|--------------------------|
| b-i: Automated compliance monitoring for SOC 2, ISO 27001, PCI-DSS, GDPR | AWS Config rules + Azure Policies mapped to all four frameworks |
| b-ii: Continuous compliance assessment and gap analysis | AWS Config running 24/7, gap analysis reports in `reports/` folder |
| b-iii: Automated audit evidence collection | `aws-config-compliance.json` + `policy-assignments.json` = audit evidence |

---

*Module 2 of 6 — Enterprise Cloud Security Operations Platform*
