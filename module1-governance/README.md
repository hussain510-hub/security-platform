# Module 1 — Cloud Governance

> **Multi-Cloud Security Scanning & Posture Management**
> **Status:** ✅ Complete | **Clouds:** AWS (eu-north-1) + Azure | **Platform:** GitHub Codespace

---

## Table of Contents
- [What This Module Does](#what-this-module-does)
- [Architecture Diagram](#architecture-diagram)
- [Tools Used](#tools-used)
- [Folder Structure](#folder-structure)
- [How It Works — Step by Step](#how-it-works--step-by-step)
- [Key Commands](#key-commands)
- [Outputs & Artifacts](#outputs--artifacts)
- [Compliance Mapping](#compliance-mapping)
- [How This Feeds the Next Module](#how-this-feeds-the-next-module)

---

## What This Module Does

Module 1 is the **foundation** of the entire platform. Before anything else — compliance reports, risk scores, dashboards — you first need to know what security problems exist. That is exactly what this module delivers.

It scans both AWS and Azure accounts against hundreds of security controls and produces structured findings that every other module consumes.

```
"You can't fix what you can't see."
Module 1 makes everything visible.
```

---

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                    MODULE 1 — CLOUD GOVERNANCE                   │
│                      GitHub Codespace                            │
└──────────────────────┬───────────────────────────────────────────┘
                       │
         ┌─────────────┴──────────────┐
         │                            │
┌────────▼────────┐         ┌─────────▼───────┐
│   AWS Account   │         │  Azure Account  │
│  eu-north-1     │         │  eu-north-1     │
│  IAM: sec-user  │         │  az login       │
│  SecurityAudit  │         │  CLI Auth       │
│  ViewOnlyAccess │         └─────────┬───────┘
└────────┬────────┘                   │
         │                            │
         │    ┌────────────────────┐  │
         └───►│      PROWLER       │◄─┘
              │  Multi-Cloud CSPM  │
              │  AWS + Azure scan  │
              │  CIS/GDPR/ISO/NIST │
              └────────┬───────────┘
                       │ CSV findings (;-delimited)
              ┌────────▼───────────┐
              │    SCOUTSUITE      │
              │  Visual HTML Report│
              │  AWS service view  │
              └────────┬───────────┘
                       │ scoutsuite-report/
              ┌────────▼───────────┐
              │  CLOUD CUSTODIAN   │
              │  Policy-as-Code    │
              │  S3/EC2/IAM Rules  │
              └────────┬───────────┘
                       │
         ┌─────────────▼───────────────┐
         │        OUTPUTS              │
         │  prowler-aws-*.csv          │
         │  prowler-azure-*.csv        │
         │  scoutsuite-report/*.html   │
         │  custodian-output/*.json    │
         └─────────────────────────────┘
```

---

## Tools Used

| Tool | Purpose | Why Chosen |
|------|---------|------------|
| **Prowler** | Scans AWS + Azure for hundreds of security misconfigurations | Industry-standard CSPM; maps findings directly to CIS, GDPR, ISO 27001, NIST, PCI-DSS |
| **ScoutSuite** | Generates a visual HTML dashboard broken down by AWS service | Perfect for demonstrating a clear, service-level security picture |
| **Cloud Custodian** | Runs specific policy rules (e.g., flag public S3 buckets) | Policy-as-code approach — shows automated governance in action |
| **AWS CLI** | Authenticates to AWS for Prowler and Cloud Custodian | Required for all AWS tool communication |
| **Azure CLI** | Authenticates to Azure for Prowler Azure scan | Required for Azure subscription scanning |

---

## Folder Structure

```
module1-cloud-governance/
│
├── README.md
│
├── .devcontainer/
│   └── devcontainer.json          ← Auto-installs all tools on Codespace start
│
├── prowler-output/
│   ├── aws/
│   │   ├── prowler-gdpr-aws.csv
│   │   ├── prowler-iso27001-aws.csv
│   │   ├── prowler-pci-aws.csv
│   │   └── prowler-cis-aws.csv
│   └── azure/
│       ├── prowler-gdpr-azure.csv
│       └── prowler-cis-azure.csv
│
├── scoutsuite-report/
│   └── scoutsuite-report.html     ← Visual HTML dashboard
│
└── cloud-custodian/
    ├── s3-public-block.yml        ← Policy: flag public S3 buckets
    ├── ec2-tags.yml               ← Policy: enforce resource tagging
    └── custodian-output/          ← JSON findings per policy
```

---

## How It Works — Step by Step

### Step 1 — Environment Setup

The Codespace uses a `devcontainer.json` that auto-installs everything:

```json
{
  "name": "Security Platform",
  "image": "mcr.microsoft.com/devcontainers/python:3.12",
  "features": {
    "ghcr.io/devcontainers/features/aws-cli:1": {},
    "ghcr.io/devcontainers/features/azure-cli:1": {},
    "ghcr.io/devcontainers/features/terraform:1": {}
  },
  "postCreateCommand": "pip install prowler scoutsuite c7n ansible --break-system-packages"
}
```

### Step 2 — AWS Authentication

Created a dedicated IAM user `sec-user` with **read-only** permissions (never the root account):

```
Policies attached:  SecurityAudit  +  ViewOnlyAccess
```

```bash
aws configure
# AWS Access Key ID:     [sec-user key]
# AWS Secret Access Key: [sec-user secret]
# Default region:        eu-north-1
# Output format:         json
```

### Step 3 — Azure Authentication

```bash
az login
# Logs in via browser, sets active subscription
```

### Step 4 — Prowler Scans (AWS + Azure)

```bash
# AWS — GDPR compliance scan
prowler aws --compliance gdpr_aws -f eu-north-1 --output-formats csv

# AWS — ISO 27001
prowler aws --compliance iso27001_2013_aws -f eu-north-1 --output-formats csv

# AWS — PCI-DSS
prowler aws --compliance pci_3.2.1_aws -f eu-north-1 --output-formats csv

# AWS — CIS Benchmark
prowler aws --compliance cis_1.5_aws -f eu-north-1 --output-formats csv

# Azure — GDPR
prowler azure --compliance gdpr_azure --az-cli-auth

# Azure — CIS
prowler azure --compliance cis_2.0_azure --az-cli-auth
```

### Step 5 — ScoutSuite Visual Scan (AWS only)

```bash
scout aws --report-name scoutsuite-report --no-browser
# Opens HTML dashboard showing pass/fail per AWS service
```

### Step 6 — Cloud Custodian Policy Enforcement

```bash
# Run public S3 detection policy
custodian run --output-dir=custodian-output cloud-custodian/s3-public-block.yml

# Run EC2 tagging policy
custodian run --output-dir=custodian-output cloud-custodian/ec2-tags.yml
```

---

## Key Commands

| Command | What It Does |
|---------|-------------|
| `aws configure` | Authenticate AWS CLI with sec-user credentials |
| `az login` | Authenticate Azure CLI |
| `prowler aws --compliance gdpr_aws` | Run GDPR scan on AWS |
| `prowler azure --compliance cis_2.0_azure --az-cli-auth` | Run CIS scan on Azure |
| `scout aws --report-name scoutsuite-report` | Generate ScoutSuite HTML report |
| `custodian run --output-dir=out policy.yml` | Execute a Cloud Custodian policy |

---

## Outputs & Artifacts

| File | Description | Used By |
|------|-------------|---------|
| `prowler-aws-gdpr.csv` | All AWS GDPR control findings (PASS/FAIL) | Module 2, Module 3 |
| `prowler-azure-cis.csv` | All Azure CIS control findings | Module 2, Module 3 |
| `scoutsuite-report.html` | Visual HTML dashboard by AWS service | Module 6 (Dashboard) |
| `custodian-output/*.json` | Cloud Custodian policy violation findings | Module 2 |

---

## Compliance Mapping

| Prowler Flag | Framework | Controls Checked |
|-------------|-----------|-----------------|
| `gdpr_aws` | GDPR | Encryption, logging, access control |
| `iso27001_2013_aws` | ISO 27001 | Asset management, access control, incident response |
| `pci_3.2.1_aws` | PCI-DSS | Network security, encryption, monitoring |
| `cis_1.5_aws` | CIS Benchmark | 100+ AWS hardening controls |
| `cis_2.0_azure` | CIS Azure | Azure-specific hardening controls |

---

## How This Feeds the Next Module

```
Module 1 Output                    →    Consumed By
─────────────────────────────────────────────────────
prowler-*.csv (all frameworks)     →    Module 3 (combine_prowler.py merges them)
Findings list (FAIL statuses)      →    Module 2 (used to verify Config/Policy gaps)
ScoutSuite HTML                    →    Module 6 (embedded in executive dashboard)
```

> **Key insight for the interview:** Module 1 is the only module that talks directly to the cloud accounts. Every other module either extends Module 1's findings or enforces controls based on what Module 1 discovered.
