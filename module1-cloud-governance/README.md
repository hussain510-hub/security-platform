# Module 1 — Cloud Governance

> **Multi-Cloud Security Scanning & Auto-Remediation**  
> AWS (eu-north-1) + Microsoft Azure

**Status:** ✅ Complete (including Auto-Remediation)  
**Tools:** Prowler · ScoutSuite · Cloud Custodian · AWS CLI · Azure CLI

---

## What This Module Does

Module 1 is the **foundation** of the entire security platform. Before compliance can be monitored, risks scored, or a dashboard built — we first need to know what security problems exist in the cloud accounts. Module 1 does exactly that:

1. Scans AWS and Azure infrastructure for every security misconfiguration
2. Maps every finding to compliance frameworks (GDPR, ISO 27001, PCI-DSS, CIS)
3. Automatically remediates the most critical violations using policy-as-code

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    MODULE 1 ARCHITECTURE                        │
│                                                                 │
│   AWS Account (eu-north-1)        Azure Subscription           │
│   ┌─────────────────────┐         ┌─────────────────────┐      │
│   │  IAM · EC2 · S3     │         │  Resources + Roles   │      │
│   │  VPC · RDS · etc.   │         │  Storage · Network   │      │
│   └──────────┬──────────┘         └──────────┬──────────┘      │
│              │                               │                  │
│     ┌────────▼──────────────────────────────▼──────┐           │
│     │           SCANNING LAYER                      │           │
│     │  ┌──────────┐  ┌──────────┐  ┌───────────┐   │           │
│     │  │ Prowler  │  │ScoutSuite│  │   Cloud   │   │           │
│     │  │(AWS+Azure│  │ (AWS     │  │ Custodian │   │           │
│     │  │compliance│  │ visual)  │  │ (policy-  │   │           │
│     │  │ mapping) │  │          │  │  as-code) │   │           │
│     │  └────┬─────┘  └────┬─────┘  └─────┬────┘   │           │
│     └───────┼─────────────┼──────────────┼─────────┘           │
│             │             │              │                      │
│             ▼             ▼              ▼                      │
│     ┌─────────────┐ ┌──────────┐ ┌──────────────────┐         │
│     │ HTML Report │ │  Visual  │ │ Detection Output  │         │
│     │ + 44 CSV    │ │ Dashboard│ │ + Auto-Remediation│         │
│     │ (compliance)│ │ HTML     │ │   Evidence JSON   │         │
│     └─────────────┘ └──────────┘ └──────────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Tools Overview

| Tool | Purpose | Why Chosen |
|------|---------|-----------|
| **Prowler** | Scans AWS and Azure — checks hundreds of security rules automatically | Industry standard, open-source, supports CIS/GDPR/ISO/NIST benchmarks out-of-the-box |
| **ScoutSuite** | Visual HTML dashboard of security issues per AWS service | Perfect visual report for stakeholders and examiners |
| **Cloud Custodian** | Runs policy rules AND auto-remediates violations | Policy-as-code: detection AND enforcement in one tool |
| **AWS CLI** | Command-line connection to AWS account | Required by Prowler and Cloud Custodian for authentication |
| **Azure CLI** | Command-line connection to Azure subscription | Required by Prowler to scan Azure |

---

## Folder Structure

```
module1-cloud-governance/
├── aws/
│   ├── prowler/
│   │   ├── prowler-output-[account]-[date].html     ← Full HTML report
│   │   └── compliance/                               ← 44 CSV files (one per standard)
│   └── scoutsuite/
│       └── aws-334960985321.html                     ← Visual service-level report
├── azure/
│   └── prowler/
│       └── prowler-output-[tenant]-[date].html       ← Azure scan report
└── cloud-custodian/
    ├── policies.yml                                   ← Detection-only policies
    ├── policies-remediation.yml                       ← Detection + Auto-Remediation
    ├── output/                                        ← Detection scan results
    └── remediation-output/
        └── security-groups-open-ssh-remediate/
            └── resources.json                         ← Proof: 8 SSH rules revoked
```

---

## AWS Setup

### IAM User (Least Privilege)

A dedicated `sec-user` IAM account is used — **never** the root account.

```
Policies attached:
  ├── SecurityAudit      ← Read-only view of security configurations
  └── ViewOnlyAccess     ← Read-only view of all services
```

### CLI Configuration

```bash
aws configure
# Prompts: Access Key ID, Secret Access Key, Region: eu-north-1, Output: json

# Verify connection
aws sts get-caller-identity
```

### Azure CLI Configuration

```bash
az login          # Opens browser for interactive login
az account show   # Verify subscription is connected
```

---

## Prowler — AWS Scan

### Command

```bash
prowler aws \
  --region eu-north-1 \
  --output-formats html json-ocsf \
  --output-directory module1-cloud-governance/aws/prowler/
```

### AWS Scan Results

| Metric | Number | Meaning |
|--------|--------|---------|
| Total checks run | 573 | Security rules tested |
| ✅ PASSED | 90 (50%) | Correctly configured |
| ❌ FAILED | 87 (48.33%) | Issues needing remediation |
| Most critical service | **IAM** | 24 failures — biggest risk area |

### Compliance Results

| Standard | Fail Rate | Meaning |
|----------|-----------|---------|
| GDPR | 60.98% failing | Major data privacy gaps — would fail a GDPR audit |
| ISO 27001 | 50% failing | Half of the information security standard not met |
| PCI-DSS | 69.57% failing | Would fail a payment card security audit |
| CIS Benchmark | ~57% failing | Industry security best practices not followed |

---

## Prowler — Azure Scan

```bash
prowler azure \
  --output-formats html json-ocsf \
  --output-directory module1-cloud-governance/azure/prowler/
```

The same tool and compliance mappings are used across both clouds — this gives the platform a **unified multi-cloud view** with consistent findings.

---

## ScoutSuite — Visual Security Report

### Command

```bash
scout aws --report-dir module1-cloud-governance/aws/scoutsuite/
```

### Results

| Metric | Value |
|--------|-------|
| Total findings | 351 across 17 AWS services |
| Report format | Interactive HTML dashboard |
| Key value | Visual service-level breakdown for stakeholders |

---

## Cloud Custodian — Policy-as-Code

### What is Cloud Custodian?

Cloud Custodian (c7n) lets you write security policies as YAML files. Instead of manually checking rules, you write a policy and it automatically finds (and optionally fixes) every violation. This is **Policy-as-Code**.

### Workflow

```
┌──────────────────────────────────────────────────────────────┐
│              CLOUD CUSTODIAN WORKFLOW                        │
│                                                              │
│  policies.yml              policies-remediation.yml          │
│  (Detection Only)          (Detection + Action)             │
│       │                           │                          │
│       ▼                           ▼                          │
│  ┌──────────┐             ┌──────────────┐                   │
│  │ DETECT   │             │  DRY RUN     │                   │
│  │ Violation│             │  (--dryrun)  │                   │
│  │ Found    │             │  Confirm     │                   │
│  └────┬─────┘             │  impact      │                   │
│       │                   └──────┬───────┘                   │
│       ▼                          ▼                           │
│  output/                  ┌──────────────┐                   │
│  resources.json           │  REMEDIATE   │                   │
│  (evidence)               │  Execute fix │                   │
│                           └──────┬───────┘                   │
│                                  ▼                           │
│                           remediation-output/                │
│                           resources.json                     │
│                           (audit evidence)                   │
└──────────────────────────────────────────────────────────────┘
```

### Detection Policies (`policies.yml`)

```yaml
policies:
  - name: s3-public-buckets
    resource: s3
    description: Find all S3 buckets with public access enabled
    filters:
      - type: global-grants
        allow_website: true

  - name: security-groups-open-ssh
    resource: security-group
    description: Find security groups allowing SSH from anywhere
    filters:
      - type: ingress
        IpProtocol: tcp
        FromPort: 22
        ToPort: 22
        Cidr: 0.0.0.0/0

  - name: iam-users-no-mfa
    resource: iam-user
    description: Find IAM users without MFA enabled
    filters:
      - type: mfa-device
        value: 0
        op: eq
```

### Auto-Remediation Policies (`policies-remediation.yml`)

```yaml
policies:
  # POLICY 1 — Public S3 buckets: enables all 4 Block Public Access settings
  - name: s3-public-buckets-remediate
    resource: s3
    filters:
      - type: global-grants
        allow_website: true
    actions:
      - type: set-public-block
        BlockPublicAcls: true
        IgnorePublicAcls: true
        BlockPublicPolicy: true
        RestrictPublicBuckets: true

  # POLICY 2 — Open SSH: revokes the matching ingress rule immediately
  - name: security-groups-open-ssh-remediate
    resource: security-group
    filters:
      - type: ingress
        IpProtocol: tcp
        FromPort: 22
        ToPort: 22
        Cidr: 0.0.0.0/0
    actions:
      - type: remove-permissions
        ingress: matched

  # POLICY 3 — No MFA: disables the user's access keys (safe, reversible)
  - name: iam-users-no-mfa-remediate
    resource: iam-user
    filters:
      - type: mfa-device
        value: 0
        op: eq
    actions:
      - type: remove-keys
        disable: true
```

### Remediation Summary

| Policy | Violation Detected | Automatic Action | Framework Control |
|--------|--------------------|-----------------|-------------------|
| `s3-public-buckets-remediate` | S3 bucket publicly accessible | Enables all 4 Block Public Access settings | GDPR Art.32, CIS 2.1.5 |
| `security-groups-open-ssh-remediate` | Port 22 open to 0.0.0.0/0 | Revokes matched ingress rule immediately | CIS 4.1, PCI Req.1 |
| `iam-users-no-mfa-remediate` | IAM user has no MFA device | Disables user's access keys (safe, reversible) | CIS 1.10, ISO A.9.4.2 |

### Commands

```bash
# Step 1 — Detection run
custodian run \
  --output-dir module1-cloud-governance/cloud-custodian/output \
  module1-cloud-governance/cloud-custodian/policies.yml \
  --region eu-north-1

# Step 2 — Dry run (safe, touches nothing)
custodian run \
  --output-dir module1-cloud-governance/cloud-custodian/remediation-output \
  module1-cloud-governance/cloud-custodian/policies-remediation.yml \
  --region eu-north-1 \
  --dryrun

# Step 3 — Live remediation
custodian run \
  --output-dir module1-cloud-governance/cloud-custodian/remediation-output \
  module1-cloud-governance/cloud-custodian/policies-remediation.yml \
  --region eu-north-1

# Step 4 — Inspect evidence
cat module1-cloud-governance/cloud-custodian/remediation-output/\
security-groups-open-ssh-remediate/resources.json | python3 -m json.tool | head -50
```

**Expected dry run output:**
```
policy:s3-public-buckets-remediate       count:0  (no public buckets found)
policy:security-groups-open-ssh-remediate count:8  (8 open SSH groups WILL be fixed)
policy:iam-users-no-mfa-remediate        count:0  (IAM is global, not region-scoped)
```

---

## Combined Multi-Cloud Results

| Tool | Cloud | Findings | Key Value |
|------|-------|----------|-----------|
| Prowler | AWS | 87 failed checks across 573 rules | Compliance-mapped to GDPR, ISO, CIS, NIST, PCI-DSS |
| ScoutSuite | AWS | 351 total findings across 17 services | Visual service-level breakdown for stakeholders |
| Prowler | Azure | Real Azure findings | Same compliance framework as AWS for consistency |
| Cloud Custodian (detect) | AWS | Policy violations per custom rule | Policy-as-code detection |
| Cloud Custodian (remediate) | AWS | **8 SSH security groups remediated** | Automated enforcement — CSPM objective met |

---

## Security Incident — Git Push Protection

During development, Prowler's JSON output accidentally contained AWS Access Key IDs. GitHub's Push Protection feature automatically detected the secret and **blocked the push**.

### Resolution Steps

```bash
# Create a new branch with clean history
git checkout --orphan clean-main

# Add all files (JSON outputs are in .gitignore)
git add .

# Commit fresh with no secret history
git commit -m 'Module 1: Cloud Governance - Prowler scan results'

# Replace old main branch on GitHub with clean version
git push --force origin clean-main:main
```

After resolving: credentials were rotated, and JSON output patterns were added to `.gitignore`.

---

## Key Terms

| Term | Explanation |
|------|-------------|
| **Cloud Governance** | Rules, processes, and tools that control how cloud resources are used securely |
| **Auto-Remediation** | Automatically fixing a security violation the moment it is detected |
| **CSPM** | Cloud Security Posture Management — continuous scanning and enforcement |
| **Policy-as-Code** | Writing security rules as code files for version control and automated enforcement |
| **Least Privilege** | Give users only the minimum access they need |
| **Dry Run** | Running a remediation tool in simulation mode — shows what WOULD happen |
| **CIS Benchmark** | Globally recognised security best practices for cloud environments |
| **Orphan Branch** | A git branch with no history — used to start fresh without inheriting old commits |

---

## Exam Objective Coverage

| Topic 97 Objective | How Module 1 Satisfies It |
|--------------------|--------------------------|
| a-i: Deploy unified cloud security governance across AWS, Azure, GCP | Prowler scans both AWS and Azure with unified compliance mapping |
| a-ii: Policy-as-code for consistent security controls | Cloud Custodian policies.yml — YAML-based policy-as-code |
| a-iii: CSPM with automated remediation | policies-remediation.yml — 8 SSH rules revoked, evidence in resources.json |

---

*Module 1 of 6 — Enterprise Cloud Security Operations Platform*
