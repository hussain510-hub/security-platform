# Module 4 — Architecture Validation

> **Security Gate Before Deployment — OPA · Terraform Sentinel · Terraform · Ansible**
> **Status:** ✅ Complete | **Platform:** GitHub Codespace + AWS EC2 (eu-north-1) | **EC2:** 51.20.34.243

---

## Table of Contents
- [What This Module Does](#what-this-module-does)
- [Architecture Diagram](#architecture-diagram)
- [DevSecOps Pipeline Diagram](#devsecops-pipeline-diagram)
- [Tools Used](#tools-used)
- [Folder Structure](#folder-structure)
- [Tool 1 — OPA (Open Policy Agent)](#tool-1--opa-open-policy-agent)
- [Tool 2 — Terraform Sentinel](#tool-2--terraform-sentinel)
- [Tool 3 — Terraform](#tool-3--terraform)
- [Tool 4 — Ansible](#tool-4--ansible)
- [Reports Generated](#reports-generated)
- [How This Feeds the Next Module](#how-this-feeds-the-next-module)

---

## What This Module Does

Modules 1, 2, and 3 dealt with existing cloud infrastructure — scanning what is already deployed, monitoring it, and scoring its risk. Module 4 is different: it is the **prevention** module.

```
Module 1   →   Scans existing cloud for problems          (Doctor doing a check-up)
Module 2   →   Monitors compliance continuously           (Security camera watching 24/7)
Module 4   →   Blocks insecure code BEFORE deployment     (Building inspector rejecting bad blueprints)
```

Module 4 answers the question: **"How do we make sure NEW infrastructure is secure before anyone builds it?"**

---

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                  MODULE 4 — ARCHITECTURE VALIDATION                  │
└──────────────────────────────────────────────────────────────────────┘

  Developer writes        ┌──────────────┐
  Terraform code    ────► │   TERRAFORM  │
                          │  insecure    │
                          │  -infra.tf   │
                          │  secure      │
                          │  -infra.tf   │
                          └──────┬───────┘
                                 │ generates tfplan.json
                  ┌──────────────┼──────────────┐
                  │              │              │
         ┌────────▼───────┐      │    ┌─────────▼──────┐
         │      OPA       │      │    │    SENTINEL     │
         │  Open Policy   │      │    │  Terraform-     │
         │  Agent         │      │    │  native policy  │
         │                │      │    │  engine         │
         │  rego policies │      │    │                 │
         │  encryption    │      │    │  encryption     │
         │  s3-security   │      │    │  network-sec    │
         │  sec-group     │      │    │  s3-security    │
         └────────┬───────┘      │    └─────────┬───────┘
                  │              │              │
                  │    PASS ✅   │   FAIL ❌   │
                  │   FAIL ❌    │             │
                  └──────────────┼─────────────┘
                                 │
                                 │ If PASS → Deploy
                                 ▼
                        ┌────────────────┐
                        │  AWS EC2       │
                        │  Ubuntu Server │
                        │  51.20.34.243  │
                        │  eu-north-1    │
                        └───────┬────────┘
                                │
                                ▼
                        ┌────────────────┐
                        │    ANSIBLE     │
                        │  Hardening     │
                        │  Playbook      │
                        │                │
                        │  • SSH config  │
                        │  • Firewall    │
                        │  • Auto-update │
                        │  • Fail2ban    │
                        │  • Log audit   │
                        └───────┬────────┘
                                │
                                ▼
                        ┌────────────────┐
                        │    REPORTS     │
                        │  opa-report    │
                        │  sentinel-rep  │
                        │  ansible-rep   │
                        │  module4-sum   │
                        └────────────────┘
```

---

## DevSecOps Pipeline Diagram

```
┌────────────────────────────────────────────────────────────────────┐
│                    DEVSECOPS PIPELINE                              │
│                                                                    │
│  CODE         PRE-DEPLOY          DEPLOY          POST-DEPLOY      │
│  PHASE        GATES               PHASE           HARDENING        │
│                                                                    │
│  ┌──────┐   ┌──────────────┐   ┌──────────┐   ┌─────────────┐    │
│  │Terra-│   │ OPA Policy   │   │  Cloud   │   │   Ansible   │    │
│  │form  ├──►│ Validation   ├──►│  Deploy  ├──►│  Hardening  │    │
│  │Code  │   │              │   │  (EC2,   │   │  Playbook   │    │
│  │      │   │ Sentinel     │   │   S3,    │   │             │    │
│  │      │   │ Policy Check │   │   RDS)   │   │  SSH, UFW,  │    │
│  └──────┘   │              │   └──────────┘   │  Fail2ban,  │    │
│             │ ❌ BLOCK if  │                   │  Updates    │    │
│             │ insecure     │                   └─────────────┘    │
│             └──────────────┘                                       │
│                                                                    │
│  Tools:     OPA + Sentinel        Terraform        Ansible         │
│  Stage:     Prevent               Deploy           Harden          │
└────────────────────────────────────────────────────────────────────┘
```

---

## Tools Used

| Tool | Version | What It Does | Why Used |
|------|---------|-------------|----------|
| **OPA** (Open Policy Agent) | v1.15.1 | Reads infrastructure code before deployment and blocks policy violations | Language-agnostic; works with any cloud tool; maps to GDPR/CIS/ISO 27001 |
| **Terraform Sentinel** | v0.30.0 | HashiCorp's native policy engine specifically for Terraform | Native Terraform integration; hard-mandatory enforcement level |
| **Terraform** | v1.14.8 | Writes cloud infrastructure as code — shows secure vs insecure examples | Demonstrates infrastructure-as-code approach |
| **Ansible** | core 2.20.4 | Automatically configures and hardens servers after deployment | Demonstrates automated post-deployment hardening on real EC2 |

---

## Folder Structure

```
module4-architecture/
│
├── README.md
│
├── opa/
│   ├── policies/
│   │   ├── encryption.rego           ← Block unencrypted resources
│   │   ├── s3-security.rego          ← Block public S3 buckets
│   │   └── security-group.rego       ← Block open 0.0.0.0/0 rules
│   └── test/
│       ├── insecure-input.json       ← Test input that should FAIL
│       └── secure-input.json         ← Test input that should PASS
│
├── sentinel/
│   ├── policies/
│   │   ├── encryption.sentinel       ← Enforce encryption-at-rest
│   │   ├── network-security.sentinel ← Block unrestricted ingress
│   │   └── s3-security.sentinel      ← Block public access on S3
│   ├── sentinel.hcl                  ← Sentinel config + enforcement levels
│   └── test/
│       ├── insecure-tfplan.json      ← Simulated bad Terraform plan
│       └── secure-tfplan.json        ← Simulated good Terraform plan
│
├── terraform/
│   ├── insecure-infra.tf             ← Deliberately insecure (for OPA/Sentinel demo)
│   └── secure-infra.tf               ← Properly secured infrastructure
│
├── ansible/
│   ├── hardening-playbook.yml        ← Full server hardening automation
│   └── reset-playbook.yml            ← Undo hardening (for re-demo)
│
└── reports/
    ├── opa-validation-report.txt      ← OPA PASS/FAIL results
    ├── sentinel-validation-report.txt ← Sentinel PASS/FAIL results
    ├── ansible-hardening-report-ec2.txt ← Ansible task execution log
    └── module4-summary.txt            ← Overall module summary
```

---

## Tool 1 — OPA (Open Policy Agent)

OPA uses `.rego` policies — a declarative language that describes what is and is not allowed in infrastructure.

### Installation
```bash
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod +x opa
sudo mv opa /usr/local/bin/
```

### Policies Written

**encryption.rego** — Block any resource without encryption enabled:
```rego
package security.encryption

deny[msg] {
  resource := input.resources[_]
  resource.type == "aws_ebs_volume"
  not resource.config.encrypted
  msg := sprintf("DENY: EBS volume '%v' is not encrypted", [resource.name])
}
```

**s3-security.rego** — Block public S3 buckets:
```rego
package security.s3

deny[msg] {
  resource := input.resources[_]
  resource.type == "aws_s3_bucket_acl"
  resource.config.acl == "public-read"
  msg := sprintf("DENY: S3 bucket '%v' has public-read ACL", [resource.name])
}
```

### Running OPA Validation

```bash
# Test insecure infrastructure — should produce DENY messages
opa eval \
  --data opa/policies/ \
  --input opa/test/insecure-input.json \
  "data.security" \
  --format pretty | tee reports/opa-validation-report.txt

# Test secure infrastructure — should produce no DENY messages
opa eval \
  --data opa/policies/ \
  --input opa/test/secure-input.json \
  "data.security" \
  --format pretty
```

---

## Tool 2 — Terraform Sentinel

Sentinel is HashiCorp's policy-as-code framework built specifically for Terraform, with **hard-mandatory** enforcement (cannot be overridden).

### Installation
```bash
curl -L -o sentinel.zip https://releases.hashicorp.com/sentinel/0.30.0/sentinel_0.30.0_linux_amd64.zip
unzip sentinel.zip
sudo mv sentinel /usr/local/bin/
```

### Example Sentinel Policy — Encryption

```python
# encryption.sentinel
import "tfplan/v2" as tfplan

# Get all AWS resources from the plan
aws_resources = filter tfplan.resource_changes as _, rc {
  rc.mode is "managed" and
  rc.type in ["aws_ebs_volume", "aws_s3_bucket", "aws_rds_cluster"]
}

# Deny any resource without encryption
deny_unencrypted = rule {
  all aws_resources as _, rc {
    rc.change.after.encrypted is true
  }
}

main = rule { deny_unencrypted }
```

### Running Sentinel

```bash
# Test against insecure plan — should FAIL
sentinel apply -config sentinel/sentinel.hcl \
  sentinel/policies/encryption.sentinel \
  | tee reports/sentinel-validation-report.txt
```

---

## Tool 3 — Terraform

Two infrastructure files demonstrate the difference between insecure and secure code.

### insecure-infra.tf — What NOT to Do
```hcl
# ❌ INSECURE — publicly readable S3 bucket
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "public-read"    # VIOLATION: Public access
}

# ❌ INSECURE — unencrypted EBS volume
resource "aws_ebs_volume" "data" {
  size      = 20
  encrypted = false          # VIOLATION: No encryption
}

# ❌ INSECURE — open security group
resource "aws_security_group_rule" "allow_all" {
  cidr_blocks = ["0.0.0.0/0"]  # VIOLATION: Unrestricted access
  from_port   = 0
  to_port     = 65535
}
```

### secure-infra.tf — Best Practice
```hcl
# ✅ SECURE — private S3 bucket with encryption
resource "aws_s3_bucket" "data" {
  bucket = "my-secure-data-bucket"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_ebs_volume" "data" {
  size      = 20
  encrypted = true           # ✅ Encrypted at rest
  kms_key_id = aws_kms_key.main.arn
}
```

---

## Tool 4 — Ansible

Ansible automatically hardens the deployed EC2 instance — applying 15+ security controls in one playbook execution.

### Target Server
```
EC2 Instance: Ubuntu Server
IP: 51.20.34.243
Region: eu-north-1 (Stockholm)
```

### Hardening Playbook — What It Does

```yaml
# hardening-playbook.yml
---
- name: Security Hardening Playbook
  hosts: all
  become: yes

  tasks:
    - name: Update all packages
      apt: upgrade=dist update_cache=yes

    - name: Install security tools
      apt:
        name: [ufw, fail2ban, auditd, unattended-upgrades]
        state: present

    - name: Configure UFW firewall — deny all by default
      ufw: state=enabled policy=deny

    - name: Allow SSH only
      ufw: rule=allow port=22 proto=tcp

    - name: Disable root SSH login
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^PermitRootLogin'
        line: 'PermitRootLogin no'

    - name: Disable password authentication (keys only)
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^PasswordAuthentication'
        line: 'PasswordAuthentication no'

    - name: Configure Fail2ban — ban after 3 failed attempts
      copy:
        dest: /etc/fail2ban/jail.local
        content: |
          [DEFAULT]
          maxretry = 3
          bantime = 3600

    - name: Enable automatic security updates
      copy:
        dest: /etc/apt/apt.conf.d/20auto-upgrades
        content: |
          APT::Periodic::Update-Package-Lists "1";
          APT::Periodic::Unattended-Upgrade "1";
```

### Running Ansible

```bash
# Run hardening playbook on EC2
ansible-playbook ansible/hardening-playbook.yml \
  -i 51.20.34.243, \
  --private-key ~/.ssh/your-key.pem \
  -u ubuntu \
  | tee reports/ansible-hardening-report-ec2.txt
```

---

## Reports Generated

| Report | Description | Key Evidence |
|--------|-------------|-------------|
| `opa-validation-report.txt` | OPA PASS/FAIL per policy per resource | Shows which insecure resources were blocked |
| `sentinel-validation-report.txt` | Sentinel PASS/FAIL results | Shows hard-mandatory enforcement in action |
| `ansible-hardening-report-ec2.txt` | Task-by-task Ansible execution log | Proves 15+ controls applied to live EC2 |
| `module4-summary.txt` | Overall module validation summary | High-level PASS/FAIL count |

---

## How This Feeds the Next Module

```
Module 4 Output              →    Consumed By
──────────────────────────────────────────────
opa-validation-report.txt    →    Module 6 (architecture score in dashboard)
sentinel-report.txt          →    Module 6 (policy gate results)
ansible-report.txt           →    Module 6 (hardening evidence)
```

> **Key insight for the interview:** The four tools cover three distinct stages of the deployment pipeline. OPA and Sentinel are pre-deployment gates — they stop bad code before it touches the cloud. Terraform shows what the infrastructure looks like as code. Ansible hardens the server after deployment. Together, they form a complete DevSecOps pipeline — from commit to hardened server.
