# Module 3 — Cloud Risk Management

> **FAIR Risk Scoring · Business Impact Analysis · Risk Treatment Planning · STRIDE Threat Modelling**
> AWS (eu-north-1) + Microsoft Azure

**Status:** ✅ Complete
**Tools:** Python · pandas · Prowler CSVs · FAIR Model · STRIDE Framework
**Output:** Risk-scored CSV · Top 10 risks · BIA financial exposure report · Threat model report

---

## What This Module Does

Module 1 discovered hundreds of security problems. Module 3 answers the next question:

> *"We found security problems — but how serious are they financially? What is the actual risk to the business?"*

Module 3 has four jobs:

1. **Score** every security finding by how dangerous it is → Risk Engine
2. **Calculate** the expected annual financial loss each finding could cause → FAIR Model (ALE)
3. **Calculate** total money at risk if a whole business system goes down → Business Impact Analysis (BIA)
4. **Classify** every finding by attack type and link a security control → STRIDE Threat Model

---

## Architecture & Data Pipeline

```
┌──────────────────────────────────────────────────────────────────────┐
│               MODULE 3 — RISK MANAGEMENT PIPELINE                   │
│                                                                      │
│  INPUT                                                               │
│  ┌──────────────────────────────────────────────────────────┐       │
│  │  Module 1 Outputs                                        │       │
│  │  AWS compliance CSVs (44 files) + Azure compliance CSVs  │       │
│  └──────────────────────┬───────────────────────────────────┘       │
│                         │                                            │
│                         ▼                                            │
│  STEP 1: combine_prowler.py                                          │
│  ┌──────────────────────────────────────────────────────────┐       │
│  │  Merges all Prowler CSVs into one unified dataset        │       │
│  │  Adds Source_File column for traceability                │       │
│  │  Output: prowler_combined.csv (1,247 findings)           │       │
│  └──────────────────────┬───────────────────────────────────┘       │
│                         │                                            │
│                         ▼                                            │
│  STEP 2: risk_engine.py                                              │
│  ┌──────────────────────────────────────────────────────────┐       │
│  │  Filters FAILED findings only (847 records)              │       │
│  │  Assigns Risk Score = Criticality × Impact (1–10)        │       │
│  │  Calculates FAIR ALE = TEF × Vulnerability × Loss Mag.  │       │
│  │  Assigns Risk Treatment recommendation                   │       │
│  │  Output: risk_report.csv + top_10_risks.csv              │       │
│  └──────────────────────┬───────────────────────────────────┘       │
│                         │                                            │
│                         ▼                                            │
│  STEP 3: bia_report.py                                               │
│  ┌──────────────────────────────────────────────────────────┐       │
│  │  Maps findings to business assets (IAM, EC2, S3, etc.)   │       │
│  │  Calculates RTO + RPO per asset                          │       │
│  │  Calculates financial exposure ($) per asset per hour    │       │
│  │  Output: bia_report.csv                                  │       │
│  └──────────────────────┬───────────────────────────────────┘       │
│                         │                                            │
│                         ▼                                            │
│  STEP 4: threat_model.py                                             │
│  ┌──────────────────────────────────────────────────────────┐       │
│  │  Reads risk_report.csv                                   │       │
│  │  Maps each service to STRIDE threat categories           │       │
│  │  Links a security control to each finding                │       │
│  │  Derives Threat Likelihood from existing Risk Level      │       │
│  │  Output: threat_model_report.csv                         │       │
│  └──────────────────────────────────────────────────────────┘       │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Folder Structure

```
module3-risk-management/
├── input/
│   └── prowler_combined.csv        ← All Prowler findings merged (1,247 rows)
├── output/
│   ├── risk_report.csv             ← Full scored report (every failed finding)
│   ├── top_10_risks.csv            ← Top 10 highest risk findings
│   ├── bia_report.csv              ← Business financial exposure per asset
│   └── threat_model_report.csv     ← STRIDE threat categories + linked controls
└── scripts/
    ├── combine_prowler.py          ← Step 1: Merge all Prowler CSVs
    ├── risk_engine.py              ← Step 2: Score risks + calculate FAIR ALE
    ├── bia_report.py               ← Step 3: Business Impact Analysis
    └── threat_model.py             ← Step 4: STRIDE threat model + controls
```

---

## Step-by-Step Execution

Run all four scripts in order. Each step produces output that feeds into the next.

```
combine → score → BIA → threat model
```

### Step 1 — Combine All Prowler Findings

```bash
cd module3-risk-management/scripts
python combine_prowler.py
```

**What it does:**
1. Reads every `.csv` file from the AWS and Azure compliance folders (44+ files)
2. Prowler uses semicolons `;` between columns — the script handles this automatically
3. Adds a `Source_File` column so each row can be traced back to its original scan
4. Stacks all files into one unified table

**Expected output:**
```
Combined 8 files
Total findings: 1,247
```

---

### Step 2 — Score Every Finding (FAIR Risk Engine)

```bash
python risk_engine.py
```

**What it does:**
1. Filters to FAILED findings only (847 records)
2. Assigns a **custom Risk Score** (Criticality × Impact)
3. Calculates a **FAIR ALE** (Annual Loss Expectancy in USD)
4. Assigns a **Risk Treatment** recommendation
5. Outputs the full scored report and top 10 list

**Expected output:**
```
Total FAILED findings: 847
Risk report saved: output/risk_report.csv
Top 10 risks saved: output/top_10_risks.csv
```

---

### Step 3 — Business Impact Analysis

```bash
python bia_report.py
```

**What it does:**
1. Groups findings by business asset type (IAM, EC2, S3, RDS, etc.)
2. Calculates Recovery Time Objective (RTO) and Recovery Point Objective (RPO)
3. Estimates financial exposure per asset per hour of downtime
4. Outputs the BIA report

**Expected output:**
```
BIA report saved: output/bia_report.csv
Total financial exposure: $XXX,XXX
```

---

### Step 4 — Threat Model (STRIDE)

```bash
python threat_model.py
```

**What it does:**
1. Reads `risk_report.csv` produced by Step 2
2. Maps every cloud service to its STRIDE threat categories
3. Links a specific security control recommendation to each finding
4. Derives a qualitative Threat Likelihood from the existing Risk Level
5. Outputs `threat_model_report.csv` — all original columns plus three new ones

**Expected output:**
```
Threat Model Report
======================================================================
Service  : EC2
Threats  : Spoofing, Elevation of Privilege
Control  : Restrict SG to known CIDRs; enable IMDSv2; patch OS
...
======================================================================
Total findings        : 847
Threats mapped        : 847  (100.0%)
Unmapped (Unknown)    : 0    (0.0%)
Critical findings     : XX
High findings         : XX
======================================================================
threat_model_report.csv saved to output/
```

---

## Risk Scoring Model

### Custom Risk Score

Each finding is scored using a **two-factor model**:

```
Risk Score = Criticality Score × Impact Score

Where:
  Criticality = How dangerous the service is (1–5 scale)
  Impact      = Severity of the misconfiguration (1–5 scale based on Prowler severity)

Maximum score = 25 (normalised to 10-point scale)
```

### Service Criticality Weights

| AWS Service | Criticality | Rationale |
|-------------|-------------|-----------|
| IAM | 5/5 | Controls ALL access — compromise = full account takeover |
| EC2 | 4/5 | Compute layer — direct attack surface |
| RDS | 4/5 | Contains sensitive data |
| S3 | 4/5 | Data storage — public buckets = data breach |
| VPC / Security Groups | 4/5 | Network perimeter |
| CloudTrail / CloudWatch | 3/5 | Logging — missing = blind spots |
| Lambda | 3/5 | Serverless execution |
| ELB / API Gateway | 3/5 | External entry points |

---

## FAIR Risk Model

FAIR (Factor Analysis of Information Risk) is the industry standard framework for **quantifying risk in financial terms**.

### FAIR Formula

```
ALE (Annual Loss Expectancy) = TEF × Vulnerability × Loss Magnitude

Where:
  TEF  = Threat Event Frequency (how many times this type of attack
         is attempted per year — based on industry data)
  Vuln = Probability the attack succeeds given the vulnerability exists (0–1)
  Loss = Financial impact if the attack succeeds (USD)

  ALE = Expected financial loss per year if this finding is not fixed
```

### FAIR Scoring Table (Top Categories)

| Finding Type | TEF / year | Vulnerability | Loss Magnitude | Annual Loss (ALE) |
|-------------|-----------|--------------|---------------|-------------------|
| IAM — No MFA | 200 | 0.80 | $5,000 | $800,000 |
| S3 — Public bucket | 150 | 0.90 | $10,000 | $1,350,000 |
| SSH open to 0.0.0.0/0 | 365 | 0.70 | $8,000 | $2,044,000 |
| No CloudTrail logging | 100 | 0.50 | $15,000 | $750,000 |
| Unencrypted EBS | 50 | 0.60 | $20,000 | $600,000 |

> **Note:** These figures use conservative industry-standard estimates from FAIR research. Actual values vary by organisation size and regulatory environment.

---

## Risk Treatment Framework

| Risk Score | Risk Level | Recommended Treatment |
|-----------|-----------|----------------------|
| 8–10 | 🔴 Critical | **Mitigate immediately** — fix within 24 hours |
| 6–7 | 🟠 High | **Mitigate** — fix within 1 week |
| 4–5 | 🟡 Medium | **Mitigate or Transfer** — fix within 1 month |
| 2–3 | 🟢 Low | **Accept or Monitor** — schedule for next quarter |
| 1 | ⚪ Informational | **Accept** — monitor only |

---

## Business Impact Analysis (BIA)

The BIA maps every security finding to the business asset it affects and calculates financial exposure.

### BIA Methodology

```
For each Business Asset:

  RTO (Recovery Time Objective)  = Maximum acceptable downtime
  RPO (Recovery Point Objective) = Maximum acceptable data loss window

  Hourly Financial Exposure = (Annual Revenue ÷ 8,760 hours) × Business Impact Factor

  Total Exposure = Hourly Exposure × RTO hours
```

### BIA Results by Asset

| Business Asset | RTO | RPO | Hourly Exposure | Risk Level |
|----------------|-----|-----|----------------|-----------|
| IAM / Identity Platform | 1 hr | 0 hr | $50,000/hr | 🔴 Critical |
| Customer Data (S3/RDS) | 4 hrs | 1 hr | $30,000/hr | 🔴 Critical |
| Compute (EC2 fleet) | 2 hrs | 30 min | $25,000/hr | 🟠 High |
| Network / VPC | 1 hr | 0 hr | $40,000/hr | 🔴 Critical |
| Logging / Monitoring | 24 hrs | 1 hr | $5,000/hr | 🟡 Medium |
| API Services | 2 hrs | 15 min | $20,000/hr | 🟠 High |

---

## STRIDE Threat Model

After scoring every finding with FAIR and the custom risk engine, the threat model layer classifies each finding by attack category using the **STRIDE framework** and links a specific security control.

### What is STRIDE?

STRIDE is a threat classification framework developed by Microsoft. Each letter represents a category of attack:

| Letter | Threat Category | Plain English Meaning |
|--------|----------------|-----------------------|
| **S** | Spoofing | Pretending to be someone or something else (fake identity, stolen credentials) |
| **T** | Tampering | Unauthorised modification of data or configuration |
| **R** | Repudiation | Denying an action occurred — no audit trail to prove otherwise |
| **I** | Information Disclosure | Exposing sensitive data to unauthorised parties |
| **D** | Denial of Service | Overloading or blocking access to a service so it becomes unavailable |
| **E** | Elevation of Privilege | Gaining higher access rights than authorised — attackers escalating to admin level |

### How `threat_model.py` Works

The script adds three new columns to `risk_report.csv`:

| New Column | What It Contains | Example (EC2) |
|-----------|-----------------|---------------|
| `STRIDE_Threats` | Which STRIDE categories apply to this service | Spoofing, Elevation of Privilege |
| `Linked_Control` | The recommended security control to address the threat | Restrict SG to known CIDRs; enable IMDSv2; patch OS |
| `Threat_Likelihood` | Likelihood derived from the existing Risk Level column | Very High (mapped from Critical) |

### Threat Likelihood Mapping

| Risk Level | Threat Likelihood |
|-----------|------------------|
| Critical | Very High |
| High | High |
| Medium | Medium |
| Low | Low |

### STRIDE Mapping — Cloud Services

| Service | STRIDE Threats | Linked Control |
|---------|---------------|----------------|
| EC2 | Spoofing, Elevation of Privilege | Restrict SG to known CIDRs; enable IMDSv2; patch OS |
| S3 | Information Disclosure, Tampering | Set ACL private; enable versioning, MFA delete, and encryption |
| IAM | Spoofing, Elevation of Privilege | Enforce MFA; apply least privilege; rotate access keys |
| IAM Access Analyzer | Elevation of Privilege | Enable IAM Access Analyzer; remediate external access findings |
| EBS | Tampering, Information Disclosure | Encrypt all EBS volumes at rest; enforce backup plans |
| Lambda | Elevation of Privilege | Apply least-privilege execution role; enable X-Ray tracing |
| CloudTrail | Repudiation | Enable multi-region trail; encrypt with KMS; enable log validation |
| CloudWatch | Repudiation | Enable log metric filters; create alarms for critical events |
| AWS Config | Repudiation, Tampering | Enable AWS Config rules; auto-remediate non-compliant resources |
| GuardDuty | Information Disclosure | Enable GuardDuty all regions; route findings to Security Hub |
| SecurityHub | Information Disclosure | Enable Security Hub; integrate GuardDuty, Config, and Inspector |
| Inspector | Information Disclosure | Enable Inspector v2; patch Critical/High CVEs within SLA |
| VPC | Denial of Service, Spoofing | Enable VPC Flow Logs; tighten NACLs; audit route tables |
| Network Firewall | Denial of Service | Deploy Network Firewall with deny-by-default stateful rules |
| ECR | Tampering, Information Disclosure | Enable image scanning on push; enforce immutable tags |
| AWS Organizations | Elevation of Privilege | Enforce SCPs at OU level; enable all AWS Org features |
| Azure Virtual Machines | Spoofing, Elevation of Privilege | Enable JIT VM access; apply NSG rules; encrypt OS disks |
| Entra ID / Azure AD | Spoofing, Elevation of Privilege | Enforce MFA in Entra ID; enable Conditional Access policies |
| Azure Monitor | Repudiation | Enable diagnostic settings on all resources; set alert rules |
| Microsoft Defender | Information Disclosure | Enable Microsoft Defender plan for all resource types |
| Azure API Management | Spoofing, Denial of Service | Enable API gateway auth; apply rate limiting and WAF policy |

### Output File — `threat_model_report.csv`

Contains all columns from `risk_report.csv` plus:

| Column | Description |
|--------|-------------|
| `STRIDE_Threats` | Comma-separated list of applicable STRIDE categories |
| `Linked_Control` | Recommended control action for the service |
| `Threat_Likelihood` | Qualitative likelihood: Very High / High / Medium / Low |

---

## Top 10 Risks

Based on Risk Score × FAIR ALE, the top 10 findings requiring immediate attention:

| Rank | Service | Finding | Risk Score | FAIR ALE (USD) | Treatment |
|------|---------|---------|------------|----------------|-----------|
| 1 | IAM | Users without MFA | 10/10 | $800,000 | Mitigate Now |
| 2 | Security Groups | SSH open to internet | 9/10 | $2,044,000 | Mitigate Now |
| 3 | S3 | Public bucket | 9/10 | $1,350,000 | Mitigate Now |
| 4 | CloudTrail | Logging disabled | 8/10 | $750,000 | Mitigate Now |
| 5 | IAM | Overly permissive policies | 8/10 | $900,000 | Mitigate Now |
| 6 | EBS | Unencrypted volumes | 7/10 | $600,000 | Mitigate — 1 week |
| 7 | RDS | Unencrypted database | 7/10 | $600,000 | Mitigate — 1 week |
| 8 | Security Groups | RDP open to internet | 7/10 | $1,200,000 | Mitigate — 1 week |
| 9 | S3 | Versioning disabled | 5/10 | $200,000 | Mitigate — 1 month |
| 10 | IAM | Password policy too weak | 5/10 | $300,000 | Mitigate — 1 month |

---

## Compliance Mapping

| Finding | GDPR | ISO 27001 | PCI-DSS | CIS |
|---------|------|-----------|---------|-----|
| No MFA | Art.32 | A.9.4.2 | Req.8.3 | 1.10 |
| Public S3 | Art.32 | A.13.2 | Req.3 | 2.1.5 |
| Open SSH | Art.32 | A.13.1 | Req.1 | 4.1 |
| Logging off | Art.30 | A.12.4 | Req.10 | 3.1 |
| No encryption | Art.32 | A.10.1 | Req.3 | — |

---

## Exam Objective Coverage

| Topic 97 Objective | How Module 3 Satisfies It |
|--------------------|--------------------------|
| c-i: Cloud risk assessment frameworks with automated scoring | `risk_engine.py` — Criticality × Impact scoring on real Prowler data |
| c-ii: Automated risk scoring and prioritization | Risk Score column + `top_10_risks.csv` auto-generated |
| c-i: FAIR risk models | `FAIR_ALE_USD` column — TEF × Vulnerability × Loss Magnitude |
| c-iii: Business impact analysis and risk treatment planning | `bia_report.py` — RTO + RPO + financial exposure per asset |
| c-iv: Threat modelling and control mapping | `threat_model.py` — STRIDE categories + linked controls per service |

---

*Module 3 of 6 — Enterprise Cloud Security Operations Platform*
