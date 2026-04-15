# Module 5 — IAM Governance

> **AWS IAM Analysis · Privilege Escalation Detection · Azure IAM Analysis · Governance Report**  
> AWS (us-east-1) + Microsoft Azure

**Status:** ✅ Complete  
**Tools:** AWS CLI · Azure CLI · Python (custom scripts)  
**Key Finding:** Overall IAM Security Score — **36/100 (Critical)**

---

## What This Module Does

Module 5 focuses on the **people side** of cloud security:

> *"Who has access to what — and should they really have it?"*

IAM (Identity and Access Management) controls who can log into cloud accounts and what they can do inside them. Bad IAM is one of the leading causes of real-world cloud breaches.

Module 5 has four jobs:

1. Analyse every AWS IAM user — permissions, MFA status, last login
2. Detect privilege escalation paths — users who can secretly give themselves admin access
3. Find over-provisioned and inactive accounts that increase the attack surface
4. Analyse Azure role assignments and find overprivileged users

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    MODULE 5 ARCHITECTURE                             │
│                                                                      │
│   AWS Account                        Azure Subscription             │
│   ┌───────────────────────┐          ┌───────────────────────┐      │
│   │  IAM Users (9 total)  │          │  Role Assignments (6) │      │
│   │  ├── admin-dave        │          │  ├── Owner (x3)        │      │
│   │  ├── svc-backup        │          │  ├── Contributor (x2)  │      │
│   │  ├── dev-alice          │          │  └── Reader (x1)       │      │
│   │  └── 6 test users      │          └──────────┬────────────┘      │
│   └────────────┬──────────┘                     │                   │
│                │                                 │                   │
│                ▼                                 ▼                   │
│   ┌──────────────────────────────────────────────────────────┐      │
│   │                    ANALYSIS LAYER                        │      │
│   │                                                          │      │
│   │  Step 1: AWS Credential Report                           │      │
│   │  aws iam generate-credential-report                      │      │
│   │              │                                           │      │
│   │              ▼                                           │      │
│   │  Step 2: privilege_escalation_detector.py                │      │
│   │  • Reads every IAM user's policies                       │      │
│   │  • Checks for dangerous permissions:                     │      │
│   │    iam:AttachUserPolicy, iam:CreateUser, wildcard *      │      │
│   │  • Finds 2 CRITICAL users                                │      │
│   │              │                                           │      │
│   │              ▼                                           │      │
│   │  Step 3: access_optimization.py                          │      │
│   │  • Checks MFA status for all users                       │      │
│   │  • Identifies ghost accounts (never logged in)           │      │
│   │  • Detects unused access keys                            │      │
│   │  • Finds 16 total issues                                 │      │
│   │              │                                           │      │
│   │              ▼                                           │      │
│   │  Step 4: azure_iam_analysis.py                           │      │
│   │  • Lists all role assignments across subscription        │      │
│   │  • Flags Owner/Contributor at subscription level         │      │
│   │  • Finds 7 total issues (3 critical, 4 high)             │      │
│   │              │                                           │      │
│   │              ▼                                           │      │
│   │  Step 5: iam_governance_report.py                        │      │
│   │  • Combines all findings into one professional report    │      │
│   │  • Maps every finding to ISO27001 / PCI-DSS / CIS / NIST│      │
│   │  • Gives overall score: AWS 32/100, Azure 41/100         │      │
│   └──────────────────────────────────────────────────────────┘      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Folder Structure

```
module5-iam-governance/
├── privilege_escalation_detector.py    ← Step 2: Finds priv-esc paths
├── escalation_findings.txt             ← Evidence: 2 critical users found
├── access_optimization.py              ← Step 3: Finds ghost accounts, no-MFA
├── access_optimization_findings.txt    ← Evidence: 16 issues found
├── credential_report.csv               ← Raw AWS report of all users
├── azure_iam_analysis.py               ← Step 4: Finds overprivileged Azure roles
├── azure_iam_findings.txt              ← Evidence: 7 issues found
├── iam_governance_report.py            ← Step 5: Combines into final report
└── iam_governance_report.txt           ← Final professional governance report
```

---

## Step-by-Step Execution

### Step 1 — Generate AWS Credential Report

```bash
# Generate the report
aws iam generate-credential-report

# Download it as CSV
aws iam get-credential-report --query 'Content' --output text | base64 -d > credential_report.csv

# Verify the report
head -5 credential_report.csv
```

The credential report contains one row per IAM user with: password status, MFA status, last login time, access key age, and whether keys have ever been used.

---

### Step 2 — Privilege Escalation Detection

```bash
python3 privilege_escalation_detector.py
```

**What the script checks:**

```
For every IAM user and every policy attached to them:
  ┌──────────────────────────────────────────────────────────────┐
  │  DANGEROUS PERMISSIONS THAT ENABLE PRIVILEGE ESCALATION      │
  │                                                              │
  │  iam:AttachUserPolicy  → User can attach ANY policy to self  │
  │  iam:CreateUser        → User can create new admin accounts  │
  │  iam:PutUserPolicy     → User can add inline policies        │
  │  iam:AttachRolePolicy  → User can escalate via roles         │
  │  Wildcard "*" on IAM   → User has full IAM control           │
  └──────────────────────────────────────────────────────────────┘
```

**Findings:**

```
[!!] CRITICAL: svc-backup
     Permission: iam:AttachUserPolicy
     Risk: This service account can attach AdministratorAccess to itself
           at any time — becoming a full admin without anyone approving it
     Fix:  Remove iam:AttachUserPolicy, limit to s3:GetObject only

[!!] CRITICAL: admin-dave
     Permission: * (wildcard) on all IAM actions
     Risk: Full IAM control — can create users, assign any permission,
           bypass all access controls
     Fix:  Replace with specific named permissions only
```

**Evidence file:** `escalation_findings.txt`

---

### Step 3 — Access Optimization

```bash
python3 access_optimization.py
```

**What the script checks:**

| Check | Finding | Count |
|-------|---------|-------|
| MFA disabled | Users with no MFA device | 9/9 users (100%) |
| Ghost accounts | Users who have never logged in | 7/9 users |
| Inactive access keys | Keys not used in 90+ days | Multiple |
| Over-provisioned | Users with more permissions than needed | Admin-dave |

**Output:**
```
Total issues found: 16

MFA Issues (9):
  - root: MFA disabled ← CRITICAL
  - admin-dave: MFA disabled ← CRITICAL
  - svc-backup: MFA disabled
  - dev-alice: MFA disabled
  - dev-bob: MFA disabled
  - [4 more test users]

Ghost Accounts — Never Logged In (7):
  - dev-bob, dev-charlie, dev-diana, dev-eve,
    dev-frank, dev-grace, dev-henry
  These accounts increase the attack surface with no business value
```

**Evidence file:** `access_optimization_findings.txt`

---

### Step 4 — Azure IAM Analysis

```bash
# Verify Azure connection
az account show

# List all role assignments
az role assignment list --all --output table

# Run analysis script
python3 azure_iam_analysis.py
```

**Azure Role Definitions:**

| Azure Role | Plain English | Risk Level |
|-----------|--------------|-----------|
| **Owner** | Master key — can do everything including give others access | CRITICAL |
| **Contributor** | Can create and delete resources but cannot give others access | HIGH |
| **Reader** | Can only view — cannot change anything | LOW |

**Findings:**

```
[!!] CRITICAL FINDINGS (3)

User: az-admin@muhammadhussainzahid5gmail.onmicrosoft.com
Role: Owner
Scope: Entire subscription
Issue: Owner role at subscription level — full control of everything
Fix:   Limit Owner role to specific resource groups only

[!] HIGH RISK FINDINGS (4)

User: az-guest@muhammadhussainzahid5gmail.onmicrosoft.com
Role: Contributor
Scope: Entire subscription
Issue: Contributor at subscription level — can create/delete anything
Fix:   Guest accounts should have Reader role maximum

SUMMARY
Total role assignments scanned: 6
Critical findings: 3
High risk findings: 4
Total issues found: 7
```

**Evidence file:** `azure_iam_findings.txt`

---

### Step 5 — IAM Governance Report

```bash
python3 iam_governance_report.py
python3 iam_governance_report.py > iam_governance_report.txt
```

**Report structure:**
- Executive Summary — one paragraph for non-technical readers
- Part 1: AWS Findings — privilege escalation, no MFA, ghost accounts
- Part 2: Azure Findings — Owner at subscription level, overprivileged roles
- Risk Score Table — every finding scored 1 to 10
- Compliance Mapping — which ISO27001, PCI-DSS, CIS, NIST controls each finding violates
- Remediation Plan — Priority 1 (do now), Priority 2 (this week), Priority 3 (this month)
- Overall Security Score

---

## Findings Summary

### Risk Score Table

| Finding | Cloud | Risk Level | Score |
|---------|-------|-----------|-------|
| Privilege escalation (svc-backup) | AWS | 🔴 CRITICAL | 10/10 |
| Wildcard admin (admin-dave) | AWS | 🔴 CRITICAL | 10/10 |
| Owner at subscription level | Azure | 🔴 CRITICAL | 9/10 |
| No MFA on any account | AWS | 🟠 HIGH | 8/10 |
| Guest with Contributor role | Azure | 🟠 HIGH | 7/10 |
| Ghost accounts (7 users) | AWS | 🟠 HIGH | 7/10 |
| Dev Contributor at subscription | Azure | 🟡 MEDIUM | 5/10 |

### Overall IAM Security Score

| Account | Score | Risk Level |
|---------|-------|-----------|
| AWS | 32 / 100 | 🔴 Critical |
| Azure | 41 / 100 | 🔴 Critical |
| **Combined** | **36 / 100** | **🔴 Critical** |

---

## Compliance Standards Mapping

| Standard | Control | What It Requires | Finding That Violates It |
|----------|---------|-----------------|--------------------------|
| ISO 27001 | A.9.1.1 | Access control policy must exist | No MFA policy, overprivileged roles |
| ISO 27001 | A.9.2.1 | User access must be formally managed | Ghost accounts never reviewed |
| ISO 27001 | A.9.2.5 | Access rights reviewed regularly | 7 accounts never logged in, never reviewed |
| ISO 27001 | A.9.4.2 | Secure log-on procedures | MFA not enabled on any account |
| PCI-DSS | Req 7.1 | Restrict access to need-to-know | admin-dave has full admin unnecessarily |
| PCI-DSS | Req 8.3 | MFA required for admin access | 9/9 users have no MFA |
| CIS AWS | 1.10 | MFA enabled for all console users | 9 users with MFA disabled |
| CIS AWS | 1.12 | Inactive credentials must be removed | 7 ghost accounts with credentials |
| CIS AWS | 1.16 | Admin privileges not given unnecessarily | admin-dave with full admin access |
| CIS Azure | 1.23 | Owner role should not be at subscription level | 3 Owner assignments at subscription |
| NIST CSF | PR.AC-1 | Identity management and access control in place | No formal IAM review process |
| NIST CSF | PR.AC-4 | Access permissions minimized | Multiple over-provisioned accounts |

---

## Remediation Plan

### Priority 1 — Do Now (Critical)

```
1. Enable MFA on the root account immediately
2. Enable MFA on admin-dave immediately
3. Remove iam:AttachUserPolicy from svc-backup — replace with s3:GetObject only
4. Replace admin-dave's wildcard (*) policy with specific named permissions
5. Review and reduce Owner role assignments at Azure subscription level
```

### Priority 2 — This Week (High)

```
6. Enable MFA on all remaining IAM users
7. Disable or delete the 7 ghost accounts that have never logged in
8. Move az-guest from Contributor to Reader role in Azure
```

### Priority 3 — This Month (Medium)

```
9. Implement quarterly access reviews for all IAM users
10. Set up automated alerts for any IAM policy changes
11. Implement Just-In-Time access for privileged operations
```

---

## Test Environment Note

Since the initial AWS account had only 2 real users, realistic test users were created so the scripts had meaningful data to analyse. This is standard practice in lab and exam environments. The test users (`dev-alice` through `dev-henry`) simulate a realistic enterprise IAM environment with varied permission levels and access patterns.

---

## Exam Objective Coverage

| Topic 97 Objective | How Module 5 Satisfies It |
|--------------------|--------------------------|
| e-i: Cloud IAM governance with automated role management and access reviews | `privilege_escalation_detector.py` + `access_optimization.py` scan all users and policies automatically |
| e-ii: Privilege escalation detection and automated remediation | Detects `iam:AttachUserPolicy`, wildcard `*`, `CreateUser` paths with specific remediation recommendations |
| e-iii: Identity risk assessment and access optimization automation | `access_optimization.py` finds ghost accounts, no-MFA users, inactive access keys |
| a-i: Unified cloud security governance across AWS and Azure | `azure_iam_analysis.py` scans Azure role assignments at subscription level |
| b-iii: Automated audit evidence collection | `iam_governance_report.py` — full report with ISO27001, PCI-DSS, CIS, NIST mapping |

---

*Module 5 of 6 — Enterprise Cloud Security Operations Platform*
