# Cloud Security Executive Dashboard — Automated Metrics Pipeline

An automated pipeline that parses raw multi-cloud security scan output (AWS + Azure) across five governance modules and generates a live executive dashboard — with every number traced back to a real source file.

This was built to satisfy three requirements:

1. **Comprehensive cloud security metrics collection and analysis**
2. **Executive dashboard automation with risk and compliance summaries**
3. **Trend analysis and security posture improvement tracking**

## Architecture

```
Module 1-5 raw reports (CSV / JSON / Markdown / TXT)
                │
                ▼
      generate_metrics.py   ──►  metrics.json        (auditable, machine-generated)
                                  trend_history.json  (appends one point per run)
                │
                ▼
      render_dashboard.py   ──►  dashboard.html       (what gets presented)
```

Two independent stages:

- **`generate_metrics.py`** is the automation layer. It never hardcodes a value — every number is parsed, computed, or aggregated directly from a source file. This is what makes the dashboard re-runnable rather than hand-edited.
- **`render_dashboard.py`** is purely presentational. It reads `metrics.json` and writes the HTML. Change the visuals here without touching how any number is calculated.

Re-run both whenever the underlying scan reports change — manually, via cron, or in CI:

```bash
pip install pandas --break-system-packages   # one-time

python3 generate_metrics.py \
    --root /path/to/security-platform \
    --out metrics.json \
    --history trend_history.json

python3 render_dashboard.py \
    --metrics metrics.json \
    --out dashboard.html
```

Example daily cron entry:

```cron
0 6 * * * cd /path/to/repo && python3 generate_metrics.py --root /path/to/security-platform --out metrics.json --history trend_history.json && python3 render_dashboard.py --metrics metrics.json --out dashboard.html
```

## What the dashboard shows

| Section | Computed from |
|---|---|
| Executive summary | Aggregated across all modules, generated fresh each run |
| Prowler results (12,608 checks: FAIL / PASS / MANUAL) | All AWS + Azure Prowler compliance CSVs (Module 1), concatenated |
| Framework compliance (GDPR, ISO 27001, PCI-DSS) | Module 2 markdown compliance reports |
| SOC2 compliance | Computed live from Prowler rows tagged `FRAMEWORK == 'SOC2'` — **not** a hardcoded estimate |
| AWS Config rule status | `aws-config-compliance.json` |
| FAIR risk register + ALE | Module 3 `top_10_risks.csv` |
| Business Impact Analysis (BIA) | Module 3 `bia_report.csv` |
| STRIDE threat model summary | Module 3 `threat_model_report.csv` |
| OPA policy gate results | Module 4 `opa-validation-report.txt` |
| Terraform Sentinel results | Module 4 `sentinel-validation-report.txt` |
| Ansible hardening recap | Module 4 `ansible-hardening-report-ec2.txt` (PLAY RECAP line) |
| AWS IAM findings (MFA, ghost accounts) | Module 5 `credential_report.csv` |
| Azure IAM findings (Owner/Contributor at subscription scope) | Module 5 `azure_iam_findings.txt` |
| IAM risk scores (AWS / Azure / combined) | Computed live with a documented formula — shown on the dashboard itself, not a black box |
| Overall security score | Weighted blend of IAM score, average compliance, and Prowler pass rate — formula shown on the dashboard |
| Trend chart | `trend_history.json` — one point appended automatically per pipeline run |
| Pipeline provenance | Full list of every source file read during that run, printed at the bottom of the dashboard |

## Scoring formulas

**SOC2 compliance:**
```
PASS / (PASS + FAIL), computed over Prowler rows where FRAMEWORK == 'SOC2'
```

**IAM scores (out of 100):**
```
AWS score   = 100 − 6×(users without MFA, capped at 54) − 15×(privilege-escalation findings, capped at 30)
Azure score = 100 − 20×(Owner-at-subscription assignments, capped at 60) − 8×(Contributor-at-subscription assignments, capped at 32)
Combined    = average(AWS score, Azure score)
```

**Overall security score:**
```
0.35 × IAM combined score + 0.35 × average compliance % + 0.30 × (100 − Prowler fail %)
```

All inputs to these formulas are counts pulled directly from the source files, not constants — every figure on the dashboard can be traced back through the formula to a file in this repo.

## Trend tracking

`trend_history.json` is append-only: each pipeline run adds one `{date, security_score, avg_compliance}` entry (re-running on the same day updates rather than duplicates that day's entry). On a single assessment this will show one data point, clearly labeled as a baseline rather than a fabricated multi-month trend. The mechanism is real and will produce an actual trend line across repeated scan cycles.

## Requirements

- Python 3.10+
- `pandas` (`pip install pandas --break-system-packages`)

## Repository layout expected by the pipeline

```
security-platform/
├── module1-cloud-governance/
│   ├── aws/prowler/compliance/*.csv
│   └── azure/prowler/compliance/*.csv
├── module2-automated-compliance/reports/
│   ├── aws-config-compliance.json
│   ├── gdpr-compliance-report.md
│   ├── iso27001-compliance-report.md
│   └── pci-dss-compliance-report.md
├── module3-risk-management/output/
│   ├── top_10_risks.csv
│   ├── bia_report.csv
│   └── threat_model_report.csv
├── module4-architecture-validation/reports/
│   ├── opa-validation-report.txt
│   ├── sentinel-validation-report.txt
│   └── ansible-hardening-report-ec2.txt
└── module5-iam-governance/
    ├── credential_report.csv
    ├── azure_iam_findings.txt
    └── remediation_report.txt
```
