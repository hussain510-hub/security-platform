import subprocess
import json

print("=" * 60)
print("  MODULE 5 - AZURE IAM ANALYSIS")
print("  Scanning Azure role assignments for risks")
print("=" * 60)

# ── STEP 1: Get the subscription ID ─────────────────────────
# The subscription ID is like the address of your Azure account
# We need it to know WHERE to scan

print("\n[*] Getting Azure subscription details...")
result = subprocess.run(
    ["az", "account", "show", "--output", "json"],
    capture_output=True, text=True
)
account = json.loads(result.stdout)
subscription_id = account["id"]
subscription_name = account["name"]
print(f"    Subscription: {subscription_name}")
print(f"    ID: {subscription_id}")

# ── STEP 2: Get ALL role assignments ────────────────────────
# This gets every single permission assignment in the subscription
# Like asking: who has what key to which room?

print("\n[*] Fetching all role assignments...")
result = subprocess.run(
    ["az", "role", "assignment", "list", "--all", "--output", "json"],
    capture_output=True, text=True
)
assignments = json.loads(result.stdout)
print(f"    Found {len(assignments)} role assignments")

# ── STEP 3: Get all users from Active Directory ──────────────
# Active Directory is Microsoft's system for managing user accounts
# Like the HR database of your Azure organisation

print("\n[*] Fetching all Azure AD users...")
result = subprocess.run(
    ["az", "ad", "user", "list", "--output", "json"],
    capture_output=True, text=True
)
users = json.loads(result.stdout)
print(f"    Found {len(users)} users in Azure AD")

# ── STEP 4: Analyse each role assignment for risks ───────────
# These are the dangerous roles we look for
# Owner and Contributor at subscription level = too powerful

HIGH_RISK_ROLES = ["Owner"]
MEDIUM_RISK_ROLES = ["Contributor"]

# This is what a subscription scope looks like
# If the scope IS the subscription = access to everything
SUBSCRIPTION_SCOPE = f"/subscriptions/{subscription_id}"

findings = []

for assignment in assignments:
    principal = assignment.get("principalName", "Unknown")
    role = assignment.get("roleDefinitionName", "Unknown")
    scope = assignment.get("scope", "")

    # Check if this role applies to the entire subscription
    # If scope equals exactly the subscription path = very broad access
    is_subscription_level = scope == SUBSCRIPTION_SCOPE

    # Check if this is a guest account
    # Guest accounts in Azure have #EXT# in their username
    # EXT stands for External user
    is_guest = "#EXT#" in str(principal)

    # ── Risk Check 1: Owner at subscription level ────────────
    if role in HIGH_RISK_ROLES and is_subscription_level:
        findings.append({
            "risk": "CRITICAL",
            "user": principal,
            "role": role,
            "scope": "Entire subscription",
            "issue": "Owner role at subscription level — full control of everything",
            "recommendation": "Limit Owner role to specific resource groups only"
        })

    # ── Risk Check 2: Contributor at subscription level ──────
    elif role in MEDIUM_RISK_ROLES and is_subscription_level:
        findings.append({
            "risk": "HIGH",
            "user": principal,
            "role": role,
            "scope": "Entire subscription",
            "issue": "Contributor at subscription level — can create/delete anything",
            "recommendation": "Limit Contributor to specific resource groups only"
        })

    # ── Risk Check 3: Guest account with powerful role ───────
    if is_guest and role in HIGH_RISK_ROLES + MEDIUM_RISK_ROLES:
        findings.append({
            "risk": "HIGH",
            "user": principal,
            "role": role,
            "scope": scope,
            "issue": "External guest account has powerful role — should have minimal access",
            "recommendation": "Remove guest access or limit to Reader role only"
        })

# ── STEP 5: Print the findings ───────────────────────────────

print("\n" + "=" * 60)
print("  AZURE IAM ANALYSIS REPORT")
print("=" * 60)

if not findings:
    print("\n[OK] No high risk role assignments found.")
else:
    critical = [f for f in findings if f["risk"] == "CRITICAL"]
    high = [f for f in findings if f["risk"] == "HIGH"]

    if critical:
        print(f"\n[!!] CRITICAL FINDINGS ({len(critical)})")
        print("-" * 60)
        for f in critical:
            print(f"     User:           {f['user']}")
            print(f"     Role:           {f['role']}")
            print(f"     Scope:          {f['scope']}")
            print(f"     Issue:          {f['issue']}")
            print(f"     Fix:            {f['recommendation']}")
            print()

    if high:
        print(f"\n[!]  HIGH RISK FINDINGS ({len(high)})")
        print("-" * 60)
        for f in high:
            print(f"     User:           {f['user']}")
            print(f"     Role:           {f['role']}")
            print(f"     Scope:          {f['scope']}")
            print(f"     Issue:          {f['issue']}")
            print(f"     Fix:            {f['recommendation']}")
            print()

# ── STEP 6: User summary table ───────────────────────────────

print("=" * 60)
print("  ALL AZURE USERS SUMMARY")
print("=" * 60)
for user in users:
    name = user.get("displayName", "Unknown")
    upn = user.get("userPrincipalName", "Unknown")
    is_guest = "#EXT#" in upn
    account_type = "GUEST" if is_guest else "MEMBER"
    print(f"  {name:25s} | {account_type:6s} | {upn}")

# ── STEP 7: Final summary ────────────────────────────────────

print("\n" + "=" * 60)
print("  SUMMARY")
print("=" * 60)
critical_count = len([f for f in findings if f["risk"] == "CRITICAL"])
high_count = len([f for f in findings if f["risk"] == "HIGH"])
print(f"  Total role assignments scanned:  {len(assignments)}")
print(f"  Critical findings:               {critical_count}")
print(f"  High risk findings:              {high_count}")
print(f"  Total issues found:              {len(findings)}")
print("=" * 60)
print("\n  Compliance mapping:")
print("  ISO27001 A.9.1  — Access control policy")
print("  ISO27001 A.9.2  — User access management")
print("  PCI-DSS Req 7   — Restrict access to need-to-know")
print("  CIS Azure 1.x   — IAM best practices")
print("=" * 60)
