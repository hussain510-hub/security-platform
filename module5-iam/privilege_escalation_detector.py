import subprocess
import json

print("=" * 60)
print("  MODULE 5 - PRIVILEGE ESCALATION DETECTOR")
print("  AWS IAM Security Analysis")
print("=" * 60)

DANGEROUS_PERMISSIONS = [
    "iam:AttachUserPolicy",
    "iam:CreateAccessKey",
    "iam:CreateUser",
    "iam:PutUserPolicy",
    "iam:AddUserToGroup",
]

def get_all_users():
    print("\n[*] Fetching all IAM users...")
    result = subprocess.run(
        ["aws", "iam", "list-users", "--output", "json"],
        capture_output=True, text=True
    )
    data = json.loads(result.stdout)
    users = [u["UserName"] for u in data["Users"]]
    print(f"    Found {len(users)} users: {', '.join(users)}")
    return users

def get_user_policies(username):
    result = subprocess.run(
        ["aws", "iam", "list-attached-user-policies",
         "--user-name", username, "--output", "json"],
        capture_output=True, text=True
    )
    data = json.loads(result.stdout)
    return data["AttachedPolicies"]

def get_policy_permissions(policy_arn):
    result = subprocess.run(
        ["aws", "iam", "get-policy", "--policy-arn", policy_arn, "--output", "json"],
        capture_output=True, text=True
    )
    policy_data = json.loads(result.stdout)
    version_id = policy_data["Policy"]["DefaultVersionId"]

    result2 = subprocess.run(
        ["aws", "iam", "get-policy-version",
         "--policy-arn", policy_arn,
         "--version-id", version_id, "--output", "json"],
        capture_output=True, text=True
    )
    version_data = json.loads(result2.stdout)
    statements = version_data["PolicyVersion"]["Document"]["Statement"]

    permissions = []
    for statement in statements:
        if statement["Effect"] == "Allow":
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            permissions.extend(actions)
    return permissions

def check_wildcard(permissions):
    return "*" in permissions or "iam:*" in permissions

def scan_user(username):
    findings = []
    policies = get_user_policies(username)
    if not policies:
        return findings
    for policy in policies:
        permissions = get_policy_permissions(policy["PolicyArn"])
        if check_wildcard(permissions):
            findings.append({
                "risk": "CRITICAL",
                "issue": "Has wildcard (*) permission — instant admin access",
                "policy": policy["PolicyName"]
            })
        for perm in DANGEROUS_PERMISSIONS:
            if perm in permissions:
                findings.append({
                    "risk": "CRITICAL",
                    "issue": f"Has '{perm}' — can escalate privileges",
                    "policy": policy["PolicyName"]
                })
    return findings

users = get_all_users()
all_findings = {}

print("\n[*] Scanning each user for privilege escalation risks...")
print("-" * 60)

for user in users:
    findings = scan_user(user)
    if findings:
        all_findings[user] = findings

print("\n" + "=" * 60)
print("  SCAN RESULTS")
print("=" * 60)

if not all_findings:
    print("\n[OK] No privilege escalation risks found.")
else:
    for user, findings in all_findings.items():
        print(f"\n[!!] USER: {user}")
        print(f"     RISK LEVEL: CRITICAL")
        print(f"     FINDINGS:")
        for f in findings:
            print(f"       - [{f['risk']}] {f['issue']}")
            print(f"         Policy: {f['policy']}")

print("\n" + "=" * 60)
print(f"  SUMMARY: {len(all_findings)} user(s) with escalation risks found")
print("=" * 60)
