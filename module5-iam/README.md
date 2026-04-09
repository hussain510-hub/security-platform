# Module 5 — IAM Governance

> **AWS IAM Analysis · Privilege Escalation Detection · Azure IAM · Access Optimization**
> **Status:** ✅ Complete | **Clouds:** AWS (us-east-1) + Azure | **Tools:** AWS CLI, Azure CLI, Python

---

## Table of Contents
- [What This Module Does](#what-this-module-does)
- [Architecture Diagram](#architecture-diagram)
- [IAM Risk Landscape](#iam-risk-landscape)
- [Test Environment Setup](#test-environment-setup)
- [Pipeline Overview](#pipeline-overview)
- [Folder Structure](#folder-structure)
- [Script 1 — AWS Credential Report](#script-1--aws-credential-report)
- [Script 2 — privilege_escalation_detector.py](#script-2--privilege_escalation_detectorpy)
- [Script 3 — access_optimization.py](#script-3--access_optimizationpy)
- [Script 4 — azure_iam_analysis.py](#script-4--azure_iam_analysispy)
- [Script 5 — iam_governance_report.py](#script-5--iam_governance_reportpy)
- [Key Findings Summary](#key-findings-summary)
- [How This Feeds the Next Module](#how-this-feeds-the-next-module)

---

## What This Module Does

Modules 1–4 focused on the infrastructure and code side of security. Module 5 focuses on the **human side**:

```
The core question Module 5 answers:
"Who has access to what — and should they REALLY have it?"
```

Bad IAM (Identity and Access Management) is one of the **leading causes** of real-world cloud breaches. Over-privileged users, inactive accounts, missing MFA, and privilege escalation paths are all exploited by attackers. This module finds all of them automatically.

---

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                     MODULE 5 — IAM GOVERNANCE                        │
└──────────────────────────────────────────────────────────────────────┘

    ┌───────────────────────────┐    ┌──────────────────────────────┐
    │        AWS Account        │    │         Azure Account        │
    │        us-east-1          │    │                              │
    │                           │    │  Subscription Level          │
    │  IAM Users: 7 (test env)  │    │  Role Assignments            │
    │  Policies: Custom+AWS     │    │  Owner/Contributor roles     │
    └────────────┬──────────────┘    └──────────────┬───────────────┘
                 │                                  │
                 ▼                                  ▼
    ┌────────────────────────┐      ┌───────────────────────────────┐
    │  STEP 1                │      │  STEP 4                       │
    │  aws iam               │      │  azure_iam_analysis.py        │
    │  generate-credential   │      │                               │
    │  -report               │      │  • List all role assignments  │
    │                        │      │  • Find Owner-level users     │
    │  credential_report.csv │      │  • Flag overprivileged roles  │
    └────────────┬───────────┘      └──────────────┬────────────────┘
                 │                                  │
                 ▼                                  │
    ┌────────────────────────┐                      │
    │  STEP 2                │                      │
    │  privilege_escalation  │                      │
    │  _detector.py          │                      │
    │                        │                      │
    │  Scans all IAM policies│                      │
    │  for dangerous actions:│                      │
    │  • iam:AttachUserPolicy│                      │
    │  • iam:CreateUser      │                      │
    │  • iam:CreateAccessKey │                      │
    │  • wildcard * on IAM   │                      │
    │                        │                      │
    │  escalation_findings   │                      │
    │  .txt (2 CRITICAL)     │                      │
    └────────────┬───────────┘                      │
                 │                                  │
                 ▼                                  │
    ┌────────────────────────┐                      │
    │  STEP 3                │                      │
    │  access_optimization   │                      │
    │  .py                   │                      │
    │                        │                      │
    │  • Ghost accounts      │                      │
    │  • No-MFA users        │                      │
    │  • Inactive access keys│                      │
    │  • Over-privileged     │                      │
    │                        │                      │
    │  16 issues found       │                      │
    └────────────┬───────────┘                      │
                 │                                  │
                 └───────────────┬──────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │  STEP 5                │
                    │  iam_governance_report │
                    │  .py                   │
                    │                        │
                    │  Combines ALL findings │
                    │  Maps to standards:    │
                    │  ISO27001, PCI-DSS,    │
                    │  CIS, NIST             │
                    │                        │
                    │  iam_governance_report │
                    │  .txt                  │
                    └───────────┬────────────┘
                                │
                                ▼
                       ┌────────────────┐
                       │   MODULE 6     │
                       │   Dashboard    │
                       │   IAM Section  │
                       └────────────────┘
```

---

## IAM Risk Landscape

```
┌──────────────────────────────────────────────────────────────────────┐
│                   IAM ATTACK SURFACE MAP                             │
│                                                                      │
│   HIGH RISK                    MEDIUM RISK            LOW RISK       │
│   ─────────                    ───────────            ────────       │
│                                                                      │
│   Privilege Escalation    →    Over-privileged   →   Inactive        │
│   Paths                        Accounts               Accounts       │
│                                                                      │
│   "User can attach          "Full admin for      "Old contractor     │
│    any policy to            a read-only job"      account still      │
│    themselves"                                    exists"            │
│                                                                      │
│   Missing MFA on          →    No Key Rotation   →   No Logging      │
│   Admin Users                                                        │
│                                                                      │
│   "Admin logs in            "90-day-old keys     "No trail of        │
│    with just a              are a breach          who did what"      │
│    password"                 waiting to happen"                      │
│                                                                      │
│   ◄── Module 5 detects ALL of these automatically ──────────────►   │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Test Environment Setup

Since the AWS account only had 2 real users, a realistic test environment was created to demonstrate the scripts meaningfully.

### AWS Test Users Created

| Username | Permissions | Purpose | Risk Level |
|----------|-------------|---------|------------|
| `admin-dave` | `AdministratorAccess` (full admin) | Overprivileged admin with wildcard `*` | 🔴 CRITICAL |
| `dev-alice` | `EC2FullAccess` + `S3FullAccess`, no MFA | Broad access, MFA missing | 🟠 HIGH |
| `dev-bob` | `EC2FullAccess` | Developer, never logged in | 🟠 HIGH |
| `analyst-carol` | `ReadOnlyAccess` | Well-scoped read-only | 🟢 LOW |
| `svc-backup` | Custom `svc-backup-policy` | **Privilege escalation path** | 🔴 CRITICAL |
| `contractor-eve` | `EC2ReadOnlyAccess` | Ghost contractor account | 🟡 MEDIUM |
| `sec-auditor` | `SecurityAudit` | Scoped audit-only access | 🟢 LOW |

### The Dangerous Policy — svc-backup-policy

The most important demo piece — a custom policy that simulates a **real-world privilege escalation** mistake:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:AttachUserPolicy",   ← Can attach ANY policy to itself → becomes admin
      "iam:CreateAccessKey",    ← Can create login keys for any user
      "iam:CreateUser"          ← Can create hidden admin backdoor accounts
    ],
    "Resource": "*"
  }]
}
```

---

## Pipeline Overview

```
Step 1            Step 2               Step 3            Step 4          Step 5
────────          ────────             ────────          ────────        ────────
Generate    →     Scan for       →     Find ghost  →     Azure IAM →     Combine
AWS cred          privilege            accounts &        analysis        → Full
report            escalation           missing MFA       (Azure)         governance
                  paths                                                  report
(AWS CLI)         (Python)             (Python)          (Python)        (Python)
```

---

## Folder Structure

```
module5-iam/
│
├── README.md
│
├── privilege_escalation_detector.py      ← Step 2: Finds users who can hack themselves to admin
├── escalation_findings.txt               ← Evidence: 2 CRITICAL users found
│
├── access_optimization.py                ← Step 3: Finds ghost accounts and no-MFA users
├── access_optimization_findings.txt      ← Evidence: 16 issues found
│
├── credential_report.csv                 ← Raw AWS report of all users (Step 1 output)
│
├── azure_iam_analysis.py                 ← Step 4: Finds overprivileged Azure roles
├── azure_iam_findings.txt                ← Evidence: 7 issues found
│
├── iam_governance_report.py              ← Step 5: Combines everything into final report
└── iam_governance_report.txt             ← Final professional governance report
```

---

## Script 1 — AWS Credential Report

AWS generates a built-in credential report listing every IAM user and their security status.

```bash
# Generate the report (takes ~15 seconds)
aws iam generate-credential-report

# Download it
aws iam get-credential-report \
  --query Content \
  --output text | base64 -d > credential_report.csv
```

**Columns in the report:**

| Column | What It Reveals |
|--------|----------------|
| `user` | IAM username |
| `password_enabled` | Does user have console access? |
| `mfa_active` | Has MFA been set up? |
| `access_key_1_last_used_date` | When was the last API call? |
| `password_last_used` | When did they last log in? |

---

## Script 2 — privilege_escalation_detector.py

```bash
python privilege_escalation_detector.py
```

**What it scans for:**

```
Dangerous IAM Actions Detected:
─────────────────────────────────────────────────
iam:AttachUserPolicy   → Can attach admin policy to itself
iam:CreateUser         → Can create hidden backdoor accounts
iam:CreateAccessKey    → Can create new access keys for any user
iam:PutUserPolicy      → Can add inline policies with full access
iam:UpdateLoginProfile → Can change any user's password
Action: "*" on iam:*   → Full IAM control = god-mode
```

**Expected output — escalation_findings.txt:**
```
=== PRIVILEGE ESCALATION FINDINGS ===

[CRITICAL] admin-dave
  Policy: AdministratorAccess
  Dangerous Actions: iam:* (wildcard)
  Risk: Full IAM control — can do anything

[CRITICAL] svc-backup
  Policy: svc-backup-policy (custom)
  Dangerous Actions: iam:AttachUserPolicy, iam:CreateUser, iam:CreateAccessKey
  Risk: Can grant itself administrator access silently
```

---

## Script 3 — access_optimization.py

```bash
python access_optimization.py
```

**What it finds:**

```
┌─────────────────────────────────────────────────────────┐
│             ACCESS OPTIMIZATION CHECKS                  │
│                                                         │
│  ✓ Ghost Accounts                                       │
│    Users who have never logged in or haven't logged in  │
│    for 90+ days — attack surface with no business value │
│                                                         │
│  ✓ Missing MFA                                          │
│    Console users without multi-factor authentication    │
│    — password alone is not sufficient for cloud access  │
│                                                         │
│  ✓ Inactive Access Keys                                 │
│    API keys not used in 90+ days — should be rotated   │
│    or deleted                                           │
│                                                         │
│  ✓ Over-Provisioned Users                               │
│    Admin access for read-only job roles                 │
│    — principle of least privilege violated              │
└─────────────────────────────────────────────────────────┘
```

**Expected output: 16 issues found across 7 users**

---

## Script 4 — azure_iam_analysis.py

```bash
python azure_iam_analysis.py
```

**What it does:**

```bash
# Lists all role assignments at subscription level
az role assignment list --all --output json

# Finds Owner-level assignments (highest privilege)
az role assignment list --all --query "[?roleDefinitionName=='Owner']"
```

**Checks performed:**
- Users with `Owner` role at subscription scope (too broad)
- Users with `Contributor` who should only be `Reader`
- Service principals with excessive permissions
- Guest users with privileged roles

**Expected output — azure_iam_findings.txt:**
```
7 issues found:
- 2 users with Owner role at subscription level (should be resource-group scoped)
- 3 users with Contributor but no business justification
- 2 guest users with privileged roles
```

---

## Script 5 — iam_governance_report.py

```bash
python iam_governance_report.py
```

Combines all findings into one professional report with compliance mapping:

```
IAM GOVERNANCE REPORT — Compliance Mapping
────────────────────────────────────────────────────────────────────

Finding: MFA not enabled on console users
  CIS Control:     CIS 1.10 — Ensure MFA is enabled for all IAM users
  ISO 27001:       A.9.4.2 — Secure log-on procedures
  PCI-DSS:         Req 8.3 — Secure individual non-consumer user auth
  NIST CSF:        PR.AC-7 — Users/processes authenticated
  Recommendation:  Enable MFA immediately for all console users

Finding: Privilege escalation path — svc-backup
  CIS Control:     CIS 1.16 — Ensure IAM policies are attached only to groups/roles
  ISO 27001:       A.9.2.3 — Management of privileged access rights
  NIST CSF:        PR.AC-4 — Access permissions managed
  Recommendation:  Remove iam:AttachUserPolicy from svc-backup-policy
```

---

## Key Findings Summary

| Category | Finding | Count | Severity |
|----------|---------|-------|----------|
| Privilege Escalation | Users who can self-escalate to admin | 2 | 🔴 CRITICAL |
| Missing MFA | Console users without MFA | 4 | 🟠 HIGH |
| Ghost Accounts | Accounts never/rarely used | 2 | 🟡 MEDIUM |
| Overprivileged | Admin access for non-admin roles | 3 | 🟠 HIGH |
| Inactive Keys | Access keys not used in 90+ days | 3 | 🟡 MEDIUM |
| Azure Issues | Overprivileged Azure role assignments | 7 | 🟠 HIGH |
| **Total** | | **21** | |

---

## How This Feeds the Next Module

```
Module 5 Output                    →    Consumed By
─────────────────────────────────────────────────────
iam_governance_report.txt          →    Module 6 (IAM section of dashboard)
escalation_findings.txt            →    Module 6 (critical alerts panel)
azure_iam_findings.txt             →    Module 6 (multi-cloud IAM summary)
Total issue count (21)             →    Module 6 (IAM risk score metric)
```

> **Key insight for the interview:** IAM is the most attacked layer of cloud security. 74% of breaches involve stolen or abused credentials (Verizon DBIR). This module demonstrates that even a small AWS account with 7 users has 21 IAM issues — in a real enterprise with thousands of users, automated IAM governance isn't optional, it's essential.
