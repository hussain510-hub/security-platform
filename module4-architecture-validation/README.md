# Module 4 — Architecture Validation

> **Pre-Deployment Security Gates · Infrastructure-as-Code Security · Server Hardening**  
> AWS (eu-north-1) — including real EC2 instance: 51.20.34.243

**Status:** ✅ Complete  
**Tools:** OPA (Open Policy Agent) · Terraform Sentinel · Terraform · Ansible  
**EC2 Instance:** Ubuntu Server — eu-north-1

---

## What This Module Does

Module 4 builds a **security gate that stops bad infrastructure before it ever gets deployed** to the cloud. This is the prevention module.

| Module | Approach | Analogy |
|--------|---------|---------|
| Module 1 | Scans existing cloud for problems | Doctor doing a check-up on a patient |
| Module 2 | Monitors compliance continuously | Security camera watching 24/7 |
| **Module 4** | **Blocks insecure code before deployment** | **Building inspector rejecting bad blueprints** |

Module 4 answers: *"How do we make sure NEW infrastructure is secure before anyone builds it?"*

---

## Architecture — Full DevSecOps Pipeline

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    MODULE 4 DEVSECOPS PIPELINE                          │
│                                                                         │
│  Developer writes Terraform code (insecure-infra.tf / secure-infra.tf)  │
│                          │                                              │
│                          ▼                                              │
│              ┌───────────────────────┐                                 │
│              │   PRE-DEPLOYMENT      │                                 │
│              │   SECURITY GATES      │                                 │
│              │                       │                                 │
│              │  ┌─────────────────┐  │                                 │
│              │  │   OPA           │  │  ◄── s3-security.rego           │
│              │  │   (Open Policy  │  │  ◄── security-group.rego        │
│              │  │    Agent)       │  │  ◄── encryption.rego            │
│              │  └────────┬────────┘  │                                 │
│              │           │           │                                 │
│              │  ┌────────▼────────┐  │                                 │
│              │  │  Terraform      │  │  ◄── s3-security.sentinel       │
│              │  │  Sentinel       │  │  ◄── encryption.sentinel        │
│              │  └────────┬────────┘  │  ◄── network-security.sentinel  │
│              └───────────┼───────────┘                                 │
│                          │                                              │
│                ┌─────────┴──────────┐                                  │
│                │                    │                                   │
│                ▼                    ▼                                   │
│         ❌ VIOLATIONS          ✅ CLEAN CODE                            │
│         BLOCKED                APPROVED                                 │
│         (7 blocked on          (0 violations on                         │
│          insecure infra)        secure infra)                           │
│                                      │                                  │
│                                      ▼                                  │
│                          ┌───────────────────────┐                     │
│                          │  Terraform deploys     │                     │
│                          │  EC2 instance to AWS   │                     │
│                          │  (51.20.34.243)         │                     │
│                          └───────────┬────────────┘                    │
│                                      │                                  │
│                                      ▼                                  │
│                          ┌───────────────────────┐                     │
│                          │  Ansible Hardening     │                     │
│                          │  Playbook runs on EC2  │                     │
│                          │  • SSH hardening        │                    │
│                          │  • UFW firewall         │                    │
│                          │  • Audit logging        │                    │
│                          │  • Password policy      │                    │
│                          │  • File permissions     │                    │
│                          └───────────────────────┘                     │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Tools Overview

| Tool | What It Does | Why Used |
|------|-------------|---------|
| **OPA** | Reads infrastructure code before deployment and blocks anything violating security rules | Language-agnostic, works with any cloud tool, maps to GDPR/CIS/ISO27001 |
| **Terraform Sentinel** | HashiCorp's built-in policy engine specifically for Terraform | Native Terraform integration, hard-mandatory enforcement level |
| **Terraform** | Writes cloud infrastructure as code — servers, databases, storage | Shows infrastructure-as-code approach with secure vs insecure examples |
| **Ansible** | Automatically configures and hardens servers after deployment | Demonstrates automated post-deployment hardening on a real EC2 instance |

---

## Tool Versions

| Tool | Version | Install Command |
|------|---------|----------------|
| Terraform | v1.14.8 | Pre-installed via devcontainer.json |
| Ansible | core 2.20.4 | `pip install ansible --break-system-packages` |
| OPA | v1.15.1 | `curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static` |
| Sentinel | v0.30.0 | `curl -L -o sentinel.zip https://releases.hashicorp.com/sentinel/0.30.0/...` |

---

## Folder Structure

```
module4-architecture-validation/
├── opa/
│   ├── policies/
│   │   ├── s3-security.rego         ← Blocks public S3 buckets
│   │   ├── security-group.rego      ← Blocks open SSH/RDP
│   │   └── encryption.rego          ← Blocks unencrypted storage
│   ├── insecure-input.json          ← Test data with intentional violations
│   └── secure-input.json            ← Test data with all violations fixed
├── terraform/
│   ├── insecure-infra.tf            ← Deliberately insecure IaC (demo only)
│   └── secure-infra.tf              ← Properly secured IaC
├── sentinel/
│   ├── sentinel.hcl                 ← Policy configuration
│   ├── policies/
│   │   ├── s3-security.sentinel
│   │   ├── encryption.sentinel
│   │   └── network-security.sentinel
│   └── test/
│       ├── insecure-tfplan.json
│       └── secure-tfplan.json
├── ansible/
│   ├── hardening-playbook.yml       ← 7-section server hardening
│   └── reset-playbook.yml           ← Restores insecure defaults for demo
└── reports/
    └── ansible-hardening-report-ec2.txt ← Evidence: real EC2 hardened
```

---

## Tool 1 — OPA (Open Policy Agent)

### What is OPA?

OPA is a policy engine that checks infrastructure code against security rules **before anything gets deployed**. Like a building inspector — before a house is built, the inspector checks the blueprint. OPA does this for cloud infrastructure code.

### OPA Policies

| Policy File | What It Blocks | Standards Mapped |
|------------|----------------|-----------------|
| `s3-security.rego` | Public S3 buckets (public-read / public-read-write ACL), Buckets without versioning | GDPR Article 32, CIS AWS 2.1.5, ISO27001 A.12.3 |
| `security-group.rego` | SSH (port 22) open to 0.0.0.0/0, RDP (port 3389) open to 0.0.0.0/0, All traffic open | CIS AWS 4.1, CIS AWS 4.2, PCI-DSS Req 1 |
| `encryption.rego` | Unencrypted EBS volumes, Unencrypted RDS databases, S3 without server-side encryption | GDPR Article 32, PCI-DSS Req 3, ISO27001 A.10.1 |

### OPA Test Data

| File | Purpose | What It Contains |
|------|---------|-----------------|
| `insecure-input.json` | The "bad" infrastructure — OPA should BLOCK this | Public S3 bucket, open SSH/RDP, unencrypted EBS + RDS |
| `secure-input.json` | The "good" infrastructure — OPA should APPROVE this | Private S3, restricted SSH, encrypted everything |

### OPA Commands

```bash
# Test 1 — S3 Security Policy against insecure infrastructure
opa eval \
  --data module4-architecture-validation/opa/policies/ \
  --input module4-architecture-validation/opa/insecure-input.json \
  --format pretty \
  "data.aws.s3.security.deny"
# Expected: ["BLOCKED: S3 bucket 'insecure_bucket' has public-read ACL. Violates GDPR Article 32 and CIS AWS 2.1.5"]

# Test 2 — Network Security Policy against insecure infrastructure
opa eval \
  --data module4-architecture-validation/opa/policies/ \
  --input module4-architecture-validation/opa/insecure-input.json \
  --format pretty \
  "data.aws.security.network.deny"
# Expected: ["BLOCKED: SSH from anywhere. Violates CIS AWS 4.1", "BLOCKED: RDP from anywhere. Violates CIS AWS 4.2"]

# Test 3 — Encryption Policy against insecure infrastructure
opa eval \
  --data module4-architecture-validation/opa/policies/ \
  --input module4-architecture-validation/opa/insecure-input.json \
  --format pretty \
  "data.aws.encryption.deny"
# Expected: 4 violations (EBS, RDS, S3 x2)

# Test 4 — All policies against SECURE infrastructure (should return empty)
opa eval --data module4-architecture-validation/opa/policies/ \
  --input module4-architecture-validation/opa/secure-input.json \
  --format pretty "data.aws.s3.security.deny"
# Expected: []
```

### OPA Results

| Infrastructure | S3 Check | Network Check | Encryption Check | Total Violations |
|---------------|----------|--------------|-----------------|-----------------|
| Insecure | ❌ 1 BLOCKED | ❌ 2 BLOCKED | ❌ 4 BLOCKED | **7 violations blocked** |
| Secure | ✅ [] Clean | ✅ [] Clean | ✅ [] Clean | **0 — APPROVED** |

---

## Tool 2 — Terraform Sentinel

### OPA vs Sentinel

| Feature | OPA | Sentinel |
|---------|-----|---------|
| Made by | Open Policy Agent (CNCF) | HashiCorp (makers of Terraform) |
| Language | `.rego` files | `.sentinel` files |
| Integration | Works with any tool | Native to Terraform / Vault / Nomad |
| Enforcement levels | Pass / Fail | advisory / soft-mandatory / **hard-mandatory** |
| Used for | Any infrastructure code | Terraform-specific policies |

### Enforcement Levels

| Level | Effect |
|-------|--------|
| `advisory` | Runs but never blocks — just warns the developer |
| `soft-mandatory` | Blocks deployment BUT a senior person can override it |
| `hard-mandatory` | **ALWAYS blocks, no override possible — not even by the CEO** |

All three Sentinel policies in this platform use **hard-mandatory**.

### Sentinel Policy Configuration (`sentinel.hcl`)

```hcl
policy "s3-security" {
  source           = "./policies/s3-security.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "encryption" {
  source           = "./policies/encryption.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "network-security" {
  source           = "./policies/network-security.sentinel"
  enforcement_level = "hard-mandatory"
}
```

### Sentinel Policies

| Policy File | What It Blocks | Enforcement Level |
|------------|----------------|-----------------|
| `s3-security.sentinel` | public-read and public-read-write S3 bucket ACLs | hard-mandatory |
| `encryption.sentinel` | EBS volumes with `encrypted=false`, RDS with `storage_encrypted=false` | hard-mandatory |
| `network-security.sentinel` | Security groups allowing SSH or RDP from 0.0.0.0/0 | hard-mandatory |

### Sentinel Commands

```bash
# Test against INSECURE infrastructure (should FAIL)
sentinel apply \
  -global "tfplan=$(cat test/insecure-tfplan.json)" \
  policies/s3-security.sentinel
# Expected: Fail - s3-security.sentinel

sentinel apply \
  -global "tfplan=$(cat test/insecure-tfplan.json)" \
  policies/encryption.sentinel
# Expected: Fail - encryption.sentinel

sentinel apply \
  -global "tfplan=$(cat test/insecure-tfplan.json)" \
  policies/network-security.sentinel
# Expected: Fail - network-security.sentinel

# Test against SECURE infrastructure (should PASS)
sentinel apply -global "tfplan=$(cat test/secure-tfplan.json)" policies/s3-security.sentinel
sentinel apply -global "tfplan=$(cat test/secure-tfplan.json)" policies/encryption.sentinel
sentinel apply -global "tfplan=$(cat test/secure-tfplan.json)" policies/network-security.sentinel
# Expected: Pass - all three
```

### Sentinel Results

| Infrastructure | s3-security | encryption | network-security |
|---------------|------------|-----------|-----------------|
| Insecure | ❌ FAIL — blocked | ❌ FAIL — blocked | ❌ FAIL — blocked |
| Secure | ✅ PASS — approved | ✅ PASS — approved | ✅ PASS — approved |

---

## Tool 3 — Terraform Infrastructure-as-Code

### Insecure vs Secure Comparison

| Resource | Insecure Version ❌ | Secure Version ✅ | Standard |
|---------|-------------------|------------------|---------|
| S3 Bucket ACL | `acl = "public-read"` | No ACL + block all public access | CIS AWS 2.1.5 |
| S3 Versioning | Missing entirely | `versioning { enabled = true }` | ISO27001 A.12.3 |
| S3 Encryption | Missing entirely | AES256 server-side encryption | GDPR Article 32 |
| Security Group SSH | `cidr_blocks = ["0.0.0.0/0"]` | `cidr_blocks = ["10.0.0.0/8"]` | CIS AWS 4.1 |
| EBS Volume | `encrypted = false` | `encrypted = true` | GDPR Article 32 |
| RDS Database | `storage_encrypted = false` | `storage_encrypted = true` | PCI-DSS Req 3 |

> **Note:** The insecure file exists for demonstration purposes only — it is never deployed to real infrastructure. Its purpose is to prove that OPA and Sentinel policies actually work.

---

## Tool 4 — Ansible Hardening Playbook

### Where Ansible Fits

```
Step 1: Developer writes Terraform code
Step 2: OPA scans the code → insecure = BLOCKED
Step 3: Sentinel scans the code → insecure = BLOCKED
Step 4: Code passes checks → Terraform deploys EC2 to AWS
Step 5: Ansible automatically runs on the new server
Step 6: Ansible hardens the server (firewall, SSH, audit logs, etc.)
Step 7: Server is now secure and ready for use ✅
```

### The Seven Hardening Sections

| Section | What It Does | Standards Covered |
|---------|-------------|------------------|
| 1. System Updates | Automatically updates all OS packages to latest versions | CIS Benchmark 1.9 |
| 2. SSH Hardening | Disables root login, forces key-only auth, limits to 3 attempts, disables X11 | CIS 5.2.6 / 5.2.7 / 5.2.8 / 5.2.12 |
| 3. Firewall (UFW) | Denies all incoming traffic by default, allows only SSH (22) and HTTPS (443) | CIS 3.5, PCI-DSS Req 1 |
| 4. Audit Logging | Installs auditd, logs all login attempts and all privileged root commands | ISO27001 A.12.4, GDPR Art.32, PCI-DSS Req 10 |
| 5. Password Policy | Sets 90-day password expiry and 7-day minimum age | CIS 5.4.1 |
| 6. Disable Services | Stops and disables telnet and FTP (old, insecure protocols) | CIS 2.1 |
| 7. File Permissions | Sets correct permissions on `/etc/passwd` (0644) and `/etc/shadow` (0640) | CIS 6.1.2 / 6.1.3 |

### Commands — Running on Real EC2 (51.20.34.243)

```bash
# Verify SSH connection
ssh -i lab-key.pem -o StrictHostKeyChecking=no ubuntu@51.20.34.243 "echo connected"
# Expected: connected

# Step 1 — Reset to insecure defaults (for demo purposes)
ansible-playbook module4-architecture-validation/ansible/reset-playbook.yml \
  --inventory "51.20.34.243," \
  --user ubuntu \
  --private-key lab-key.pem \
  -v

# Step 2 — Run hardening playbook (applies all security controls)
ansible-playbook module4-architecture-validation/ansible/hardening-playbook.yml \
  --inventory "51.20.34.243," \
  --user ubuntu \
  --private-key lab-key.pem \
  --tags "ssh,firewall,audit,password,permissions" \
  -v 2>&1 | tee module4-architecture-validation/reports/ansible-hardening-report-ec2.txt
```

### Hardening Results — Task by Task

| Task | Result | Change Applied to Server |
|------|--------|-------------------------|
| Disable root SSH login | ✅ changed | `sshd_config: PermitRootLogin no` |
| Disable password authentication | ✅ changed | `sshd_config: PasswordAuthentication no` |
| Set max auth tries = 3 | ✅ changed | `sshd_config: MaxAuthTries 3` |
| Disable X11 forwarding | ✅ changed | `sshd_config: X11Forwarding no` |
| Install UFW firewall | ✅ ok | Already installed — no change needed |
| Deny all incoming by default | ✅ ok | UFW default deny already configured |
| Enable UFW | ✅ ok | Already active |
| Install auditd | ✅ ok | Already installed |
| Add SSH audit rule | ✅ changed | Audit rule for SSH auth events added |
| Add root command audit rule | ✅ changed | All root commands now logged |
| Set password max days = 90 | ✅ changed | `/etc/login.defs: PASS_MAX_DAYS 90` |

**Ansible play recap:** `ok=11  changed=8  failed=0`

---

## Module 4 Results Summary

| Tool | Test | Result |
|------|------|--------|
| OPA | Insecure infrastructure | ❌ 7 violations blocked |
| OPA | Secure infrastructure | ✅ 0 violations — approved |
| Sentinel | Insecure infrastructure | ❌ 3 policies failed |
| Sentinel | Secure infrastructure | ✅ 3 policies passed |
| Ansible | Real EC2 hardening | ✅ 8 security changes applied |

---

## Exam Objective Coverage

| Topic 97 Objective | How Module 4 Satisfies It |
|--------------------|--------------------------|
| d-i: Automated security architecture review and design validation | OPA evaluates infrastructure JSON and returns violation messages |
| d-ii: Cloud security pattern enforcement and architecture compliance | Sentinel hard-mandatory policies enforce patterns across all Terraform code |
| d-iii: Security gate automation for cloud deployment pipelines | OPA + Sentinel sit as pre-deployment gates; Ansible provides post-deploy hardening |

---

*Module 4 of 6 — Enterprise Cloud Security Operations Platform*
