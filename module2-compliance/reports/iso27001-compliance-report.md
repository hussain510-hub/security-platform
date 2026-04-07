# ISO27001 Compliance Report
**Date:** 2026-04-07  
**Account:** AWS 334960985321 | Azure 4db9fc14-989b-40b7-be4d-5bde1c4d991a  

---

## ISO27001 Controls Assessed

| Control | Requirement | Tool Used | Status |
|---------|-------------|-----------|--------|
| A.8.1  | Asset Management - all resources tagged | Azure Policy | ✅ ENFORCED |
| A.9.1  | Access Control - strong passwords | AWS Config | ❌ FAILING |
| A.9.4  | MFA required for all users | Cloud Custodian | ❌ FAILING |
| A.10.1 | Encryption of data at rest | AWS Config | ⚠️ PARTIAL |
| A.12.4 | Audit logging must be enabled | AWS Config | ❌ FAILING |
| A.13.1 | Network security controls | Cloud Custodian | ✅ MONITORED |
| A.17.1 | Business continuity planning | AWS Config | ⚠️ PARTIAL |

---

## Findings

### Critical Gaps (Must Fix)
- **A.9.1** → IAM password policy too weak — minimum length not enforced
- **A.9.4** → IAM users found without MFA enabled
- **A.12.4** → CloudTrail disabled — no audit logs being collected

### Controls Working Well
- **A.8.1** → Azure Policy enforcing Environment tags on all resources
- **A.13.1** → Cloud Custodian monitoring open SSH and public S3 buckets

---

## Overall ISO27001 Score: 43%
**3 critical controls failing — immediate remediation required**
