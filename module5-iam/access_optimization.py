import csv
import json
import subprocess
from datetime import datetime, timezone

print("=" * 60)
print("  MODULE 5 - ACCESS OPTIMIZATION ANALYSIS")
print("  Finding over-privileged and inactive users")
print("=" * 60)

# ── STEP 1: Read the credential report CSV file ─────────────
# We already downloaded this file in the previous step
# Now we open it and read each user's details from it

print("\n[*] Reading credential report...")

users_data = []
with open("credential_report.csv", "r") as f:
    # csv.DictReader reads the CSV and uses the first row
    # as column names — so we can say row["mfa_active"]
    # instead of row[7] which is confusing
    reader = csv.DictReader(f)
    for row in reader:
        users_data.append(row)

print(f"    Loaded {len(users_data)} accounts from report")

# ── STEP 2: Analyze each user ────────────────────────────────

no_mfa_users = []        # Users with no MFA enabled
never_logged_in = []     # Users who never logged into console
inactive_keys = []       # Users with old unused access keys
ghost_accounts = []      # Users who never did anything at all

today = datetime.now(timezone.utc)

for user in users_data:
    username = user["user"]

    # Skip the root account — handled differently in AWS
    if username == "<root_account>":
        continue

    # ── Check 1: Does this user have MFA turned on? ──────────
    # mfa_active will be "false" or "true" as a string
    if user["mfa_active"] == "false":
        no_mfa_users.append(username)

    # ── Check 2: Has this user EVER logged into the console? ─
    # If password_last_used is "N/A" they never logged in
    never_used_console = user["password_last_used"] == "N/A"

    # ── Check 3: Do they have an active access key? ──────────
    has_active_key = user["access_key_1_active"] == "true"
    key_last_used = user["access_key_1_last_used_date"]

    # ── Check 4: Is their access key old and unused? ─────────
    if has_active_key and key_last_used != "N/A":
        # Convert the date string into a real date we can compare
        key_date = datetime.fromisoformat(key_last_used.replace("Z", "+00:00"))
        days_since_used = (today - key_date).days
        if days_since_used > 30:
            inactive_keys.append({
                "user": username,
                "days": days_since_used,
                "last_used": key_last_used
            })

    # ── Check 5: Ghost account — never logged in AND no key ──
    # This user exists but has never done anything at all
    if never_used_console and not has_active_key:
        ghost_accounts.append(username)

# ── STEP 3: Get policy details for over-provisioned users ───
# For each user, check what policies they have attached

print("[*] Checking user policy assignments...")

user_policies = {}
result = subprocess.run(
    ["aws", "iam", "list-users", "--output", "json"],
    capture_output=True, text=True
)
all_users = json.loads(result.stdout)["Users"]

for u in all_users:
    uname = u["UserName"]
    result2 = subprocess.run(
        ["aws", "iam", "list-attached-user-policies",
         "--user-name", uname, "--output", "json"],
        capture_output=True, text=True
    )
    policies = json.loads(result2.stdout)["AttachedPolicies"]
    if policies:
        user_policies[uname] = [p["PolicyName"] for p in policies]

# ── STEP 4: Print the full report ───────────────────────────

print("\n" + "=" * 60)
print("  ACCESS OPTIMIZATION REPORT")
print("=" * 60)

# Finding 1 — No MFA
print(f"\n[!] FINDING 1: Users with NO MFA enabled ({len(no_mfa_users)} users)")
print("    Risk: If password is stolen, account is fully compromised")
print("    Standard: ISO27001 A.9.4, CIS AWS 1.10")
for u in no_mfa_users:
    policies = user_policies.get(u, ["no policies"])
    print(f"    - {u:20s} | Policies: {', '.join(policies)}")

# Finding 2 — Ghost accounts
print(f"\n[!] FINDING 2: Ghost accounts — never logged in ({len(ghost_accounts)} users)")
print("    Risk: Unnecessary accounts increase attack surface")
print("    Recommendation: Disable or delete these accounts")
for u in ghost_accounts:
    policies = user_policies.get(u, ["no policies"])
    print(f"    - {u:20s} | Policies: {', '.join(policies)}")

# Finding 3 — Inactive access keys
print(f"\n[!] FINDING 3: Inactive access keys ({len(inactive_keys)} users)")
print("    Risk: Old unused keys are a common breach entry point")
print("    Recommendation: Rotate or deactivate keys unused for 30+ days")
for item in inactive_keys:
    print(f"    - {item['user']:20s} | Last used: {item['last_used']} ({item['days']} days ago)")

# Finding 4 — Policy summary
print(f"\n[!] FINDING 4: User permission assignments")
print("    Recommendation: Apply least-privilege — only give what is needed")
for uname, policies in user_policies.items():
    print(f"    - {uname:20s} | {', '.join(policies)}")

# ── STEP 5: Summary ─────────────────────────────────────────
print("\n" + "=" * 60)
print("  SUMMARY")
print("=" * 60)
print(f"  Users with no MFA:        {len(no_mfa_users)}")
print(f"  Ghost accounts:           {len(ghost_accounts)}")
print(f"  Inactive access keys:     {len(inactive_keys)}")
print(f"  Total issues found:       {len(no_mfa_users) + len(ghost_accounts) + len(inactive_keys)}")
print("=" * 60)
