# 🛡️ Enterprise Cloud Security Operations Platform

> **EduQual Level 6 — Diploma in Artificial Intelligence Operations (DAIOL6)**
> **Student:** Muhammad Hussain Zahid | **Institution:** Al-Nafi International College

A comprehensive, production-grade multi-cloud security operations platform covering governance, automated compliance, risk management, architecture validation, IAM governance, and executive reporting — built on AWS and Azure using open-source and cloud-native tooling.

---

## 📋 Table of Contents

- [Platform Overview](#platform-overview)
- [High-Level Architecture](#high-level-architecture)
- [Data Flow Diagram](#data-flow-diagram)
- [Module Summary](#module-summary)
- [Technology Stack](#technology-stack)
- [Compliance Frameworks](#compliance-frameworks)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Repository Structure](#repository-structure)
- [Module READMEs](#module-readmes)

---

## Platform Overview

This platform solves a real enterprise problem: **how do you continuously govern, monitor, and secure multi-cloud infrastructure at scale?**

Most organisations use cloud services across AWS and Azure simultaneously. Without a unified security platform, teams end up with blind spots — undetected misconfigurations, unchecked compliance gaps, unknown identity risks, and no single executive view of posture. This platform addresses all of that in six integrated modules.

```
PROBLEM:  Multi-cloud = multiple tools, no unified view, manual compliance checks
SOLUTION: One integrated platform — automated scanning → compliance → risk → validation → IAM → dashboard
```

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ENTERPRISE CLOUD SECURITY OPERATIONS PLATFORM            │
│                         GitHub Codespace (Python 3.12)                      │
└──────────────────────────────┬──────────────────────────────────────────────┘
                               │
              ┌────────────────┴────────────────┐
              │                                 │
    ┌─────────▼──────────┐           ┌──────────▼─────────┐
    │     AWS Account    │           │    Azure Account    │
    │   (eu-north-1)     │           │   (eu-north-1)      │
    │  IAM User: sec-user│           │  CLI Authentication │
    └────────────────────┘           └────────────────────┘
              │                                 │
              └─────────────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │   MODULE 1          │
                    │  Cloud Governance   │
                    │  Prowler + ScoutSuite│
                    │  + Cloud Custodian  │
                    └──────────┬──────────┘
                               │ Findings CSVs + HTML Reports
                    ┌──────────▼──────────┐
                    │   MODULE 2          │
                    │  Automated          │
                    │  Compliance         │
                    │  AWS Config +       │
                    │  Azure Policy +     │
                    │  Cloud Custodian    │
                    └──────────┬──────────┘
                               │ Compliance Reports (GDPR/ISO27001/PCI-DSS)
                    ┌──────────▼──────────┐
                    │   MODULE 3          │
                    │  Risk Management    │
                    │  FAIR Risk Scoring  │
                    │  + BIA + Python     │
                    └──────────┬──────────┘
                               │ risk_report.csv + top_10_risks.csv + bia_report.csv
          ┌────────────────────┼────────────────────┐
          │                    │                    │
┌─────────▼──────────┐         │         ┌──────────▼─────────┐
│   MODULE 4         │         │         │   MODULE 5         │
│   Architecture     │         │         │   IAM Governance   │
│   Validation       │         │         │   AWS + Azure IAM  │
│   OPA + Sentinel   │         │         │   Privilege Escal. │
│   Terraform +      │         │         │   Detection        │
│   Ansible          │         │         └──────────┬─────────┘
└─────────┬──────────┘         │                    │
          │                    │                    │
          └────────────────────┼────────────────────┘
                               │ All Findings Aggregated
                    ┌──────────▼──────────┐
                    │   MODULE 6          │
                    │  Executive          │
                    │  Dashboard          │
                    │  HTML Report        │
                    │  CIS+NIST+ISO 27017 │
                    └─────────────────────┘
```

---

## Data Flow Diagram

```
┌────────────┐     CSV/JSON      ┌─────────────┐    Risk Scores    ┌────────────────┐
│  Module 1  │ ───────────────►  │  Module 2   │ ───────────────►  │   Module 3     │
│  Prowler   │                   │  Compliance │                   │  FAIR Engine   │
│  Findings  │                   │  Reports    │                   │  BIA Report    │
└────────────┘                   └─────────────┘                   └───────┬────────┘
                                                                           │
                                                                           ▼
┌────────────┐                   ┌─────────────┐                   ┌────────────────┐
│  Module 4  │                   │  Module 6   │◄──────────────────│   Module 5     │
│  OPA/Senti │ ───────────────►  │  Executive  │                   │  IAM Report    │
│  nel/Ansible│                  │  Dashboard  │                   │                │
│  Reports   │                   │  (HTML)     │                   └────────────────┘
└────────────┘                   └─────────────┘
```

---

## Module Summary

| # | Module | Status | Tools | Key Output |
|---|--------|--------|-------|------------|
| 1 | [Cloud Governance](./module1-cloud-governance/README.md) | ✅ Complete | Prowler, ScoutSuite, Cloud Custodian | Security findings across AWS + Azure |
| 2 | [Automated Compliance](./module2-automated-compliance/README.md) | ✅ Complete | AWS Config, Azure Policy, Cloud Custodian | GDPR / ISO27001 / PCI-DSS reports |
| 3 | [Risk Management](./module3-risk-management/README.md) | ✅ Complete | Python, FAIR Model, pandas | FAIR risk scores + BIA financials |
| 4 | [Architecture Validation](./module4-architecture-validation/README.md) | ✅ Complete | OPA, Terraform Sentinel, Terraform, Ansible | Policy enforcement + hardened EC2 |
| 5 | [IAM Governance](./module5-iam-governance/README.md) | ✅ Complete | AWS CLI, Azure CLI, Python scripts | Privilege escalation detection + IAM report |
| 6 | [Executive Dashboard](./module6-executive-dashboard/README.md) | ✅ Complete | HTML/CSS/JS | Unified security dashboard |

---

## Technology Stack

### Cloud Providers
| Provider | Region | Purpose |
|----------|--------|---------|
| AWS | eu-north-1 (Stockholm) | Primary cloud — IAM, Config, S3, EC2 |
| Azure | eu-north-1 | Secondary cloud — Policy, IAM, Role assignments |

### Open-Source Tools
| Category | Tool | Version | Purpose |
|----------|------|---------|---------|
| Cloud Scanner | Prowler | Latest | Multi-cloud security scanning |
| Visual Audit | ScoutSuite | Latest | AWS service-level HTML dashboard |
| Policy-as-Code | Cloud Custodian | Latest | Automated governance rules |
| Compliance | AWS Config | Native | Continuous rule monitoring |
| Compliance | Azure Policy | Native | Preventive policy enforcement |
| Policy Engine | Open Policy Agent (OPA) | v1.15.1 | Infrastructure policy validation |
| Policy Engine | Terraform Sentinel | v0.30.0 | Terraform-native policy gates |
| IaC | Terraform | v1.14.8 | Infrastructure as code |
| Hardening | Ansible | core 2.20.4 | Server configuration hardening |
| Risk Engine | Custom Python | 3.12 | FAIR risk scoring + BIA |
| IAM Analysis | Custom Python | 3.12 | Privilege escalation detection |
| Dashboard | HTML/CSS/JS | — | Executive reporting |

### Development Environment
- **Platform:** GitHub Codespace
- **Base Image:** `mcr.microsoft.com/devcontainers/python:3.12`
- **Config:** `.devcontainer/devcontainer.json` (auto-installs all tools)

---

## Compliance Frameworks

| Framework | Coverage | Modules |
|-----------|----------|---------|
| **CIS Benchmarks** | AWS + Azure | M1, M2, M6 |
| **GDPR** | Data privacy controls | M1, M2, M4 |
| **ISO 27001** | Information security | M1, M2, M3, M5 |
| **PCI-DSS** | Payment card security | M1, M2 |
| **SOC 2** | Service organisation controls | M2 |
| **NIST CSF** | Cybersecurity framework | M1, M6 |
| **ISO 27017** | Cloud security controls | M6 |
| **FAIR** | Financial risk quantification | M3 |

---

## Prerequisites

### Accounts Required
- AWS Account with IAM user (`sec-user`) with `SecurityAudit` + `ViewOnlyAccess` policies
- Azure Account with CLI authentication enabled

### Local / Environment
```bash
# All auto-installed via devcontainer.json in GitHub Codespace
pip install prowler scoutsuite c7n ansible --break-system-packages

# CLI tools
aws configure          # Set AWS credentials
az login               # Set Azure credentials
```

### Environment Variables
```bash
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=eu-north-1
```

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/your-username/security-platform
cd security-platform

# 2. Open in GitHub Codespace
# (devcontainer.json auto-installs all tools)

# 3. Authenticate to clouds
aws configure
az login

# 4. Run Module 1 — Scan everything
cd module1-cloud-governance
prowler aws --compliance gdpr_aws

# 5. Run Module 2 — Deploy compliance monitoring
cd ../module2-compliance
bash aws-config/enable-config-rules.sh
bash azure-policy/deploy-azure-policies.sh

# 6. Run Module 3 — Score risks
cd ../module3-risk
python scripts/combine_prowler.py
python scripts/risk_engine.py
python scripts/bia_report.py

# 7. Run Module 4 — Validate architecture
cd ../module4-architecture
opa eval -d opa/policies/ -i opa/test/insecure-input.json "data.security"
ansible-playbook ansible/hardening-playbook.yml -i <ec2-ip>,

# 8. Run Module 5 — Analyse IAM
cd ../module5-iam
python privilege_escalation_detector.py
python access_optimization.py
python azure_iam_analysis.py
python iam_governance_report.py

# 9. View Module 6 — Executive Dashboard
open module6-dashboard/dashboard.html
```

---

## Repository Structure

```
security-platform/
│
├── README.md                              ← You are here
│
├── .devcontainer/
│   └── devcontainer.json                  ← Auto-installs all tools
│
├── module1-cloud-governance/
│   ├── README.md
│   ├── prowler-output/                    ← CSV scan results (AWS + Azure)
│   ├── scoutsuite-report/                 ← HTML visual report
│   └── cloud-custodian/                   ← Policy YAML files
│
├── module2-automated-compliance/
│   ├── README.md
│   ├── aws-config/
│   ├── azure-policy/
│   └── reports/                           ← GDPR / ISO27001 / PCI-DSS reports
│
├── module3-risk/
│   ├── README.md
│   ├── input/                             ← prowler_combined.csv
│   ├── output/                            ← risk_report.csv, top_10_risks.csv, bia_report.csv
│   └── scripts/                           ← combine_prowler.py, risk_engine.py, bia_report.py
│
├── module4-architecture/
│   ├── README.md
│   ├── opa/                               ← OPA Rego policies + test inputs
│   ├── sentinel/                          ← Sentinel policies + test plans
│   ├── terraform/                         ← Secure + insecure infra examples
│   ├── ansible/                           ← Hardening playbook
│   └── reports/                           ← Validation reports
│
├── module5-iam/
│   ├── README.md
│   ├── privilege_escalation_detector.py
│   ├── access_optimization.py
│   ├── azure_iam_analysis.py
│   ├── iam_governance_report.py
│   └── *.txt                              ← Finding reports
│
└── module6-dashboard/
    ├── README.md
    └── dashboard.html                     ← Executive HTML dashboard
```

---

## Module READMEs

| Module | README Link |
|--------|------------|
| Module 1 — Cloud Governance | [module1-cloud-governance/README.md](./module1-cloud-governance/README.md) |
| Module 2 — Automated Compliance | [module2-automated-compliance/README.md](./module2-automated-compliance/README.md) |
| Module 3 — Risk Management | [module3-risk-management/README.md](./module3-risk-management/README.md) |
| Module 4 — Architecture Validation | [module4-architecture-validation/README.md](./module4-architecture-validation/README.md) |
| Module 5 — IAM Governance | [module5-iam-governance/README.md](./module5-iam-governance/README.md) |
| Module 6 — Executive Dashboard | [module6-executive-dashboard/README.md](./module6-executive-dashboard/README.md) |

---

## 👤 Author

**Muhammad Hussain Zahid**
Diploma in Artificial Intelligence Operations — EduQual Level 6
Al-Nafi International College
📧 muhammadhussainzahid5@gmail.com
