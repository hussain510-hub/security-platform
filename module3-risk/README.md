# Module 3 — Cloud Risk Management

> **FAIR Risk Scoring · Business Impact Analysis · Risk Treatment Planning**
> **Status:** ✅ Complete | **Clouds:** AWS + Azure | **Tools:** Python, pandas, FAIR Model

---

## Table of Contents
- [What This Module Does](#what-this-module-does)
- [Architecture Diagram](#architecture-diagram)
- [FAIR Risk Model Explained](#fair-risk-model-explained)
- [Pipeline Overview](#pipeline-overview)
- [Folder Structure](#folder-structure)
- [Script 1 — combine_prowler.py](#script-1--combine_prowlerpy)
- [Script 2 — risk_engine.py](#script-2--risk_enginepy)
- [Script 3 — bia_report.py](#script-3--bia_reportpy)
- [Output Files](#output-files)
- [Risk Scoring Logic](#risk-scoring-logic)
- [How This Feeds the Next Module](#how-this-feeds-the-next-module)

---

## What This Module Does

Module 1 found security problems. Module 2 monitors them continuously. Module 3 answers the hardest question:

```
"We found security problems — but how serious are they FINANCIALLY?
 What is the actual BUSINESS RISK?"
```

This module converts raw security findings into **quantified financial risk** using the FAIR (Factor Analysis of Information Risk) framework — the industry standard for turning security data into business language that executives understand.

---

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                   MODULE 3 — RISK MANAGEMENT                         │
└──────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────┐
│  MODULE 1 OUTPUT (Input)    │
│  prowler-gdpr-aws.csv       │
│  prowler-iso27001-aws.csv   │
│  prowler-pci-aws.csv        │
│  prowler-gdpr-azure.csv     │
│  prowler-cis-azure.csv      │
└─────────────────┬───────────┘
                  │
                  ▼
┌─────────────────────────────┐
│  STEP 1: combine_prowler.py │
│                             │
│  • Reads all CSV files      │
│  • Handles ; delimiter      │
│  • Adds Source_File column  │
│  • Merges into one dataset  │
│                             │
│  Output: prowler_combined   │
│          .csv (1,247 rows)  │
└─────────────────┬───────────┘
                  │
                  ▼
┌─────────────────────────────┐
│  STEP 2: risk_engine.py     │
│                             │
│  For each FAILED finding:   │
│                             │
│  ┌─────────────────────┐    │
│  │  CUSTOM RISK SCORE  │    │
│  │  Criticality x      │    │
│  │  Impact weight      │    │
│  │  per service type   │    │
│  └──────────┬──────────┘    │
│             │               │
│  ┌──────────▼──────────┐    │
│  │  FAIR ALE SCORE     │    │
│  │  TEF x Vuln x       │    │
│  │  Loss Magnitude     │    │
│  │  = $ per year       │    │
│  └──────────┬──────────┘    │
│             │               │
│  ┌──────────▼──────────┐    │
│  │  TREATMENT PLAN     │    │
│  │  Auto-assigned by   │    │
│  │  severity level     │    │
│  └─────────────────────┘    │
│                             │
│  Output: risk_report.csv    │
│          top_10_risks.csv   │
└─────────────────┬───────────┘
                  │
                  ▼
┌─────────────────────────────┐
│  STEP 3: bia_report.py      │
│                             │
│  For each business asset:   │
│  • RTO (recovery time)      │
│  • RPO (recovery point)     │
│  • Financial exposure $     │
│  • Business impact rating   │
│                             │
│  Output: bia_report.csv     │
└─────────────────┬───────────┘
                  │
                  ▼
         ┌────────────────┐
         │  MODULE 6      │
         │  Dashboard     │
         │  (Risk section)│
         └────────────────┘
```

---

## FAIR Risk Model Explained

FAIR (Factor Analysis of Information Risk) is the international standard for quantifying cyber risk in financial terms.

```
┌─────────────────────────────────────────────────────────────────┐
│                        FAIR MODEL                               │
│                                                                 │
│   Risk = Probable Frequency × Probable Magnitude                │
│                                                                 │
│   ┌─────────────────────┐    ┌─────────────────────────────┐   │
│   │  LOSS EVENT         │    │  LOSS MAGNITUDE             │   │
│   │  FREQUENCY (LEF)    │    │                             │   │
│   │                     │    │  Primary Loss:              │   │
│   │  TEF (Threat Event  │    │  • Incident response cost   │   │
│   │  Frequency) x       │    │  • Data recovery cost       │   │
│   │  Vulnerability      │    │                             │   │
│   │  (how exploitable   │    │  Secondary Loss:            │   │
│   │  is the finding?)   │    │  • Fines (GDPR: up to 4%   │   │
│   │                     │    │    of global turnover)      │   │
│   └─────────────────────┘    │  • Reputation damage        │   │
│                               └─────────────────────────────┘   │
│                                                                 │
│   ALE (Annual Loss Expectancy) = TEF × Vulnerability × Loss     │
│                                   Magnitude                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Pipeline Overview

```
Step 1             Step 2              Step 3
combine      →     score        →      BIA
─────────────────────────────────────────────
8 CSV files        847 FAIL            Business assets
1,247 findings     findings            RTO / RPO
merged into    →   scored with    →    Financial
one dataset        Risk Score +        exposure
                   FAIR ALE $          per asset
```

---

## Folder Structure

```
module3-risk/
│
├── README.md
│
├── input/
│   └── prowler_combined.csv       ← All Prowler CSVs merged (Step 1 output)
│
├── output/
│   ├── risk_report.csv            ← Full scored report — every finding
│   ├── top_10_risks.csv           ← Top 10 highest-risk findings
│   └── bia_report.csv             ← Business financial exposure per asset
│
└── scripts/
    ├── combine_prowler.py         ← Step 1: Merges all Prowler CSVs
    ├── risk_engine.py             ← Step 2: Scores risks + calculates FAIR ALE
    └── bia_report.py              ← Step 3: Business Impact Analysis
```

---

## Script 1 — combine_prowler.py

**Purpose:** Prowler saves one CSV per compliance framework per cloud. This script merges all of them into a single dataset.

```bash
cd module3-risk/scripts
python combine_prowler.py
```

**Expected terminal output:**
```
Combined 8 files
Total findings: 1,247
Saved to: input/prowler_combined.csv
```

**What the script does:**
1. Looks in the AWS and Azure Prowler output folders
2. Finds all `.csv` files (Prowler uses `;` as delimiter, not `,`)
3. Adds a `Source_File` column to track which file each finding came from
4. Stacks all files into one unified dataset
5. Saves as `prowler_combined.csv`

---

## Script 2 — risk_engine.py

**Purpose:** Takes every FAILED finding and gives it two scores — a custom severity score and a FAIR financial loss score.

```bash
python risk_engine.py
```

**Expected terminal output:**
```
Total FAILED findings: 847
Risk scoring complete.
Top 10 risks saved to: output/top_10_risks.csv
Full report saved to:  output/risk_report.csv
```

### Columns Added to Each Finding

| Column | Description | Example Value |
|--------|-------------|---------------|
| `Risk_Score` | Custom score: Criticality × Impact (0–100) | 87 |
| `FAIR_TEF` | Threat Event Frequency per year | 12 |
| `FAIR_Vulnerability` | Exploitability score (0.0–1.0) | 0.85 |
| `FAIR_Loss_Magnitude_USD` | Estimated financial loss per event ($) | 50,000 |
| `FAIR_ALE_USD` | Annual Loss Expectancy = TEF × Vuln × Loss | $510,000 |
| `Treatment` | Auto-assigned action: Mitigate / Transfer / Accept | Mitigate |
| `Recommendation` | Specific remediation action | Enable MFA immediately |

---

## Script 3 — bia_report.py

**Purpose:** Calculates financial exposure per business system/asset — RTO, RPO, and estimated cost if each system goes down.

```bash
python bia_report.py
```

### BIA Output Columns

| Column | Description |
|--------|-------------|
| `Asset` | Business system (e.g., S3 Data Lake, IAM Control Plane) |
| `RTO` | Recovery Time Objective — how fast must it be restored? |
| `RPO` | Recovery Point Objective — how much data loss is acceptable? |
| `Financial_Exposure_USD` | Estimated cost if this asset is compromised |
| `Business_Impact` | CRITICAL / HIGH / MEDIUM / LOW |
| `Recommended_Treatment` | Risk treatment plan |

---

## Output Files

| File | Rows | Key Columns | Used By |
|------|------|-------------|---------|
| `prowler_combined.csv` | ~1,247 | All Prowler fields + Source_File | risk_engine.py |
| `risk_report.csv` | ~847 (FAIL only) | Risk_Score, FAIR_ALE_USD, Treatment | Module 6 |
| `top_10_risks.csv` | 10 | Highest FAIR_ALE findings | Module 6 dashboard |
| `bia_report.csv` | Per asset | RTO, RPO, Financial_Exposure_USD | Module 6 |

---

## Risk Scoring Logic

```
┌─────────────────────────────────────────────────────────────────┐
│                    RISK SCORE CALCULATION                       │
│                                                                 │
│  Service Weight (how critical is the affected service?)         │
│  ┌─────────────────┬──────────────────────────────────────┐     │
│  │ IAM             │ Weight: 10 (highest — identity is   │     │
│  │                 │ the keys to the kingdom)             │     │
│  ├─────────────────┼──────────────────────────────────────┤     │
│  │ S3              │ Weight: 9  (data exfiltration risk)  │     │
│  ├─────────────────┼──────────────────────────────────────┤     │
│  │ EC2             │ Weight: 8  (compute access)          │     │
│  ├─────────────────┼──────────────────────────────────────┤     │
│  │ RDS             │ Weight: 8  (database breach risk)    │     │
│  ├─────────────────┼──────────────────────────────────────┤     │
│  │ CloudTrail      │ Weight: 7  (audit trail)             │     │
│  └─────────────────┴──────────────────────────────────────┘     │
│                                                                 │
│  Severity Multiplier (from Prowler finding severity):           │
│  CRITICAL = 1.0  |  HIGH = 0.8  |  MEDIUM = 0.5  |  LOW = 0.2  │
│                                                                 │
│  Final Risk Score = Service Weight × Severity Multiplier × 10   │
└─────────────────────────────────────────────────────────────────┘
```

---

## How This Feeds the Next Module

```
Module 3 Output              →    Consumed By
──────────────────────────────────────────────
risk_report.csv              →    Module 6 (risk list in dashboard)
top_10_risks.csv             →    Module 6 (top risks widget)
bia_report.csv               →    Module 6 (financial exposure section)
FAIR ALE $ values            →    Module 6 (total $ at risk metric)
```

> **Key insight for the interview:** FAIR is the only internationally recognised framework for quantifying cyber risk in financial terms. Translating a finding like "MFA not enabled" into "$510,000 annual loss expectancy" is what turns a technical security report into a board-level conversation about budget and risk appetite.
