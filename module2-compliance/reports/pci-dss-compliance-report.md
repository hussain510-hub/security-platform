# PCI-DSS Compliance Report
**Date:** 2026-04-07  
**Account:** AWS 334960985321 | Azure 4db9fc14-989b-40b7-be4d-5bde1c4d991a  

---

## PCI-DSS Requirements Assessed

| Requirement | Description | Tool Used | Status |
|-------------|-------------|-----------|--------|
| Req 1 | Firewall controls - no open SSH | Cloud Custodian | ✅ MONITORED |
| Req 2 | No default passwords | AWS Config | ❌ FAILING |
| Req 3 | Protect stored cardholder data | AWS Config | ⚠️ PARTIAL |
| Req 4 | Encrypt data in transit | Azure Policy | ✅ ENFORCED |
| Req 7 | Restrict access to cardholder data | Cloud Custodian | ✅ MONITORED |
| Req 8 | Strong access control - MFA | AWS Config | ❌ FAILING |
| Req 10 | Track all access to network resources | AWS Config | ❌ FAILING |
| Req 12 | Information security policy | Azure Policy | ✅ ENFORCED |

---

## Findings

### Critical Gaps (Must Fix)
- **Req 2** → Weak IAM password policy detected — default-like passwords allowed
- **Req 8** → MFA not enforced on IAM users — direct violation of PCI-DSS
- **Req 10** → CloudTrail disabled — no tracking of access to resources

### Controls Working Well
- **Req 4** → Azure HTTPS policy enforcing encrypted data in transit
- **Req 1** → Cloud Custodian monitoring open SSH security groups
- **Req 12** → Azure policies enforcing security standards automatically

---

## Overall PCI-DSS Score: 50%
**3 critical requirements failing — system not ready for payment processing**
