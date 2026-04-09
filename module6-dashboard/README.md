# Module 6 — Executive Dashboard

> **Unified Security Reporting · HTML Dashboard · CIS + NIST + ISO 27017 Mapping**
> **Status:** ✅ Complete | **Output:** Single HTML file — no server required

---

## Table of Contents
- [What This Module Does](#what-this-module-does)
- [Dashboard Architecture](#dashboard-architecture)
- [Data Sources Diagram](#data-sources-diagram)
- [Dashboard Sections](#dashboard-sections)
- [How to View the Dashboard](#how-to-view-the-dashboard)
- [Compliance Framework Mapping](#compliance-framework-mapping)
- [Design Decisions](#design-decisions)

---

## What This Module Does

Module 6 is the **aggregation layer** of the entire platform. It takes the outputs of all five preceding modules and presents them in a single, unified executive dashboard that answers the question every CISO and board member asks:

```
"What is our overall security posture right now?"
```

> **Note:** This module does not run any scans, scripts, or cloud commands. All data was gathered from the outputs of Modules 1–5 and assembled into a standalone HTML file. This is intentional — the dashboard is a reporting layer, not a scanning layer.

---

## Dashboard Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                   MODULE 6 — EXECUTIVE DASHBOARD                     │
│                         dashboard.html                               │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │                    TOP METRICS BAR                             │  │
│  │  Overall Security Score  │  Compliance %  │  Total Risks  │   │  │
│  │        [72/100]          │    [68%]       │    [847]      │   │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌──────────────────────┐  ┌──────────────────────────────────────┐  │
│  │  MODULE STATUS       │  │  COMPLIANCE FRAMEWORK STATUS         │  │
│  │                      │  │                                      │  │
│  │  M1 Cloud Gov  ✅    │  │  CIS Benchmark     [██████░░] 72%   │  │
│  │  M2 Compliance ✅    │  │  GDPR              [████░░░░] 61%   │  │
│  │  M3 Risk Mgmt  ✅    │  │  ISO 27001         [█████░░░] 68%   │  │
│  │  M4 Arch Valid ✅    │  │  PCI-DSS           [████░░░░] 58%   │  │
│  │  M5 IAM Gov    ✅    │  │  NIST CSF          [██████░░] 74%   │  │
│  └──────────────────────┘  │  ISO 27017         [█████░░░] 65%   │  │
│                             └──────────────────────────────────────┘  │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │                   TOP 10 RISKS (from Module 3)                  │ │
│  │  #1  MFA disabled on root account     — CRITICAL  $510K/yr ALE │ │
│  │  #2  Public S3 bucket — data-lake     — CRITICAL  $420K/yr ALE │ │
│  │  #3  Privilege escalation — svc-backup— CRITICAL  $380K/yr ALE │ │
│  │  ...                                                            │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  ┌───────────────────────┐  ┌───────────────────────────────────────┐ │
│  │  IAM FINDINGS         │  │  TREND ANALYSIS                       │ │
│  │  (from Module 5)      │  │  Security Score over time             │ │
│  │                       │  │                                       │ │
│  │  Critical:   2        │  │  ▲                                    │ │
│  │  High:       7        │  │  │         ╱─────                    │ │
│  │  Medium:     5        │  │  │    ╱───╱                           │ │
│  │  Low:        7        │  │  │───╱                                │ │
│  │                       │  │  └────────────────────►               │ │
│  │  Total: 21 issues     │  │   Week 1   Week 2   Week 3            │ │
│  └───────────────────────┘  └───────────────────────────────────────┘ │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │         CIS + NIST CSF + ISO 27017 CONTROL MAPPING              │ │
│  │  Finding → Framework → Control ID → Status → Recommendation     │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Data Sources Diagram

```
 Module 1              Module 2              Module 3
 ─────────             ─────────             ─────────
 ScoutSuite    ──►     Compliance   ──►      Top 10
 HTML report           % scores              Risks CSV
 Findings count        (GDPR, ISO,           FAIR ALE $
                        PCI-DSS)             BIA data
      │                    │                    │
      └────────────────────┼────────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  dashboard.html  │
                  │  (Module 6)      │
                  └─────────────────┘
                           ▲
                           │
      ┌────────────────────┼────────────────────┐
      │                    │                    │
 Module 4              Module 5             Standards
 ─────────             ─────────            ─────────
 OPA/Sentinel         IAM report           CIS, NIST,
 PASS/FAIL            21 findings          ISO 27017
 Ansible              Privilege esc.       control IDs
 hardening            Azure IAM            mapped to
 report               findings             each finding
```

---

## Dashboard Sections

### Section 1 — Executive Summary Metrics

Top-level KPIs visible at a glance:

| Metric | Value | Source |
|--------|-------|--------|
| Overall Security Score | 72 / 100 | Weighted average across all modules |
| Compliance Score | 68% | Average across GDPR, ISO27001, PCI-DSS, CIS |
| Total Findings | 847 | Module 1 → Module 3 (FAIL count) |
| Critical Risks | 3 | Module 3 top_10_risks.csv |
| Financial Exposure | ~$2.1M ALE | Module 3 FAIR calculation |
| IAM Issues | 21 | Module 5 governance report |

### Section 2 — Module Status Panel

Visual indicator showing all 5 modules are complete with a summary of what each produced.

### Section 3 — Compliance Framework Scores

Progress bars for each framework showing percentage compliance:
- CIS Benchmark (AWS + Azure)
- GDPR
- ISO 27001
- PCI-DSS
- NIST CSF
- ISO 27017 (cloud-specific)

### Section 4 — Top 10 Risks

Table sourced from `module3-risk/output/top_10_risks.csv` showing:
- Finding description
- Affected service and cloud
- Severity level
- FAIR ALE (Annual Loss Expectancy in USD)
- Recommended treatment

### Section 5 — IAM Findings Panel

Summary of Module 5 findings:
- Privilege escalation paths found
- Missing MFA count
- Ghost accounts
- Azure overprivileged roles

### Section 6 — Trend Analysis

A simulated trend chart showing how the security score improves as modules are implemented week by week — demonstrating the platform's value over time.

### Section 7 — Framework Control Mapping

Detailed table mapping each finding to its specific control IDs across CIS, NIST CSF, and ISO 27017 — the format examiners and auditors expect.

---

## How to View the Dashboard

```bash
# Option 1 — Open directly in browser (no server needed)
open module6-dashboard/dashboard.html

# Option 2 — Serve locally
cd module6-dashboard
python -m http.server 8080
# Then visit: http://localhost:8080/dashboard.html

# Option 3 — In GitHub Codespace
# Right-click dashboard.html → Open with Live Server
```

---

## Compliance Framework Mapping

The dashboard includes an appendix mapping each finding to its specific control IDs:

| Framework | Control ID | Control Name | Finding |
|-----------|-----------|--------------|---------|
| CIS AWS v1.5 | 1.5 | Ensure MFA enabled on root | Root MFA not enabled |
| CIS AWS v1.5 | 2.1.1 | Ensure S3 Block Public Access | Public S3 bucket found |
| NIST CSF | PR.AC-1 | Identities managed | IAM users without MFA |
| NIST CSF | PR.DS-1 | Data-at-rest protected | Unencrypted EBS volumes |
| ISO 27017 | CLD.9.5.1 | Segregation in virtual environments | Overprivileged cloud roles |
| ISO 27017 | CLD.12.1.3 | Capacity management | No auto-scaling policies |

---

## Design Decisions

**Why a single HTML file?**
A single `.html` file requires no server, no database, and no dependencies. It can be opened on any laptop, shared by email, or embedded in a presentation — exactly what an executive dashboard needs to be.

**Why not a live dashboard (e.g., Grafana)?**
The scope of this project is a practical demonstration and oral assessment. A static HTML dashboard fully demonstrates the data aggregation, compliance mapping, and visualisation capabilities without requiring additional infrastructure to be running during the exam.

**Why HTML over PDF?**
HTML allows interactive elements (clickable risk rows, expandable sections, framework filters) that a static PDF cannot provide. It also renders identically in any browser without formatting issues.

---

> **Key insight for the interview:** The executive dashboard is the product. Everything else in the platform — the scans, the risk scores, the policy validations, the IAM analysis — exists to produce the data that goes into this dashboard. A security programme without executive reporting is invisible to the business. Module 6 makes the entire platform visible, measurable, and defensible to leadership.
