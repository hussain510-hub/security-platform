# GDPR Compliance Report
**Date:** 2026-04-07  
**Account:** AWS 334960985321 | Azure 4db9fc14-989b-40b7-be4d-5bde1c4d991a  

---

## GDPR Articles Assessed

| Article | Requirement | Tool Used | Status |
|---------|-------------|-----------|--------|
| Article 5 | Data must be processed securely | AWS Config | ❌ FAILING |
| Article 17 | Right to erasure - data must be trackable | AWS Config | ❌ FAILING |
| Article 25 | Privacy by design - encryption required | AWS Config | ⚠️ PARTIAL |
| Article 32 | Encryption of personal data | Azure Policy | ✅ ENFORCED |
| Article 44 | Data must stay in approved regions | Azure Policy | ✅ ENFORCED |

---

## Findings

### Critical Gaps
- **CloudTrail disabled** → No audit trail of who accessed data (violates Article 5, 17)
- **Weak IAM passwords** → Unauthorized access risk to personal data (violates Article 32)

### Controls in Place
- **Azure EU-only policy** → Data stays in Europe (satisfies Article 44)
- **Azure HTTPS policy** → Data encrypted in transit (satisfies Article 32)

---

## Overall GDPR Score: 40%
**2 critical gaps must be fixed before GDPR certification**
