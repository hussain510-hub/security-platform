#!/usr/bin/env python3
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
                "policy": policy["PolicyName"],
                "policy_arn": policy["PolicyArn"]
            })
        for perm in DANGEROUS_PERMISSIONS:
            if perm in permissions:
                findings.append({
                    "risk": "CRITICAL",
                    "issue": f"Has '{perm}' — can escalate privileges",
                    "policy": policy["PolicyName"],
                    "policy_arn": policy["PolicyArn"]
                })
    return findings

# ── DETECTION ────────────────────────────────────────────────────────────────

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

# ── AUTO-REMEDIATION ─────────────────────────────────────────────────────────

if not all_findings:
    print("\n[OK] No remediation needed. Exiting.")
else:
    print("\n" + "=" * 60)
    print("  AUTO-REMEDIATION STARTING...")
    print("=" * 60)

    for user, findings in all_findings.items():
        print(f"\n[FIX] Remediating: {user}")

        # Collect unique policy ARNs to detach for this user
        arns_to_detach = set()
        for f in findings:
            arns_to_detach.add((f["policy"], f["policy_arn"]))

        for policy_name, policy_arn in arns_to_detach:

            # Step 1 — Detach the risky policy
            print(f"      Detaching : {policy_name}")
            result = subprocess.run(
                ["aws", "iam", "detach-user-policy",
                 "--user-name", user,
                 "--policy-arn", policy_arn],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                print(f"      ✅ Detached : {policy_name} removed from {user}")
            else:
                print(f"      ❌ Failed   : {result.stderr.strip()}")
                continue

            # Step 2 — Attach ReadOnlyAccess as safe replacement
            print(f"      Attaching  : ReadOnlyAccess (safe replacement)")
            result2 = subprocess.run(
                ["aws", "iam", "attach-user-policy",
                 "--user-name", user,
                 "--policy-arn", "arn:aws:iam::aws:policy/ReadOnlyAccess"],
                capture_output=True, text=True
            )
            if result2.returncode == 0:
                print(f"      ✅ Replaced : ReadOnlyAccess now attached to {user}")
            else:
                print(f"      ❌ Failed   : {result2.stderr.strip()}")

    # svc-backup has a custom INLINE policy (not managed) — needs separate delete
    if "svc-backup" in all_findings:
        print(f"\n[FIX] Deleting inline policy on svc-backup")
        result = subprocess.run(
            ["aws", "iam", "delete-user-policy",
             "--user-name", "svc-backup",
             "--policy-name", "svc-backup-policy"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"      ✅ Deleted  : svc-backup-policy removed (escalation path closed)")
        else:
            print(f"      ℹ️  Skipped  : {result.stderr.strip()}")

    print("\n" + "=" * 60)
    print("  REMEDIATION COMPLETE")
    print("=" * 60)
    print(f"  Fixed {len(all_findings)} user(s)")
    print()
    print("  What was done:")
    for user in all_findings:
        print(f"  • {user} -> risky policy detached, ReadOnlyAccess applied")
    if "svc-backup" in all_findings:
        print(f"  • svc-backup -> svc-backup-policy deleted (inline)")
    print()
    print("  Compliance covered:")
    print("  • CIS AWS 1.16     — Least privilege enforced")
    print("  • ISO27001 A.9.2.3 — Privileged access managed")
    print("  • PCI-DSS Req 7.1  — Access limited to need")
    print("=" * 60)
    print()
    print("  [*] Run privilege_escalation_detector.py again")
    print("      to confirm 0 CRITICAL users remain.")
    print("=" * 60)
