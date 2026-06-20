#!/usr/bin/env python3
"""
generate_metrics.py
====================
Automated metrics pipeline for the Cloud Security Executive Dashboard.

Reads RAW reports from Modules 1-5 (Prowler CSVs, AWS Config JSON,
Module 2 markdown compliance reports, Module 3 risk/BIA/threat CSVs,
Module 4 OPA/Sentinel/Ansible text reports, Module 5 IAM text reports +
credential_report.csv) and produces ONE machine-generated metrics.json
that the dashboard (dashboard.html) renders from.

This script is the "automation" layer: re-run it any time the raw
reports change (cron, CI pipeline, or manually) and the dashboard
will reflect new numbers without hand-editing any HTML.

Usage:
    python3 generate_metrics.py --root /path/to/security-platform --out metrics.json
"""

import argparse
import csv
import json
import os
import re
from datetime import datetime, timezone

import pandas as pd


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def read_prowler_csv(path):
    """Prowler compliance CSVs are semicolon-delimited."""
    try:
        df = pd.read_csv(path, sep=";", low_memory=False, encoding="utf-8")
        return df
    except Exception as e:
        print(f"  [warn] could not read {path}: {e}")
        return None


def pct(n, d):
    if not d:
        return 0.0
    return round(100.0 * n / d, 1)


# ---------------------------------------------------------------------------
# Module 1 + 3: Prowler combined (AWS + Azure compliance CSVs)
# ---------------------------------------------------------------------------

def build_prowler_combined(root):
    """
    Mirrors module3-risk-management/scripts/combine_prowler.py:
    walks every *.csv under aws/prowler/compliance and azure/prowler/compliance
    and concatenates them. Returns the combined DataFrame.
    """
    folders = [
        os.path.join(root, "module1-cloud-governance", "aws", "prowler", "compliance"),
        os.path.join(root, "module1-cloud-governance", "azure", "prowler", "compliance"),
    ]
    frames = []
    files_used = []
    for folder in folders:
        if not os.path.isdir(folder):
            continue
        for fname in sorted(os.listdir(folder)):
            if not fname.endswith(".csv"):
                continue
            fpath = os.path.join(folder, fname)
            df = read_prowler_csv(fpath)
            if df is None or df.empty:
                continue
            df.columns = df.columns.str.strip()
            df["Source_File"] = fname
            frames.append(df)
            files_used.append(fpath)
    if not frames:
        return pd.DataFrame(), files_used
    combined = pd.concat(frames, ignore_index=True)
    return combined, files_used


def prowler_summary(df):
    if df.empty or "STATUS" not in df.columns:
        return {"total": 0, "fail": 0, "pass": 0, "manual": 0}
    counts = df["STATUS"].value_counts()
    total = int(len(df))
    return {
        "total": total,
        "fail": int(counts.get("FAIL", 0)),
        "pass": int(counts.get("PASS", 0)),
        "manual": int(counts.get("MANUAL", 0)),
        "fail_pct": pct(counts.get("FAIL", 0), total),
        "pass_pct": pct(counts.get("PASS", 0), total),
        "manual_pct": pct(counts.get("MANUAL", 0), total),
    }


def framework_coverage(df, top_n=9):
    if df.empty or "FRAMEWORK" not in df.columns:
        return []
    vc = df["FRAMEWORK"].value_counts().head(top_n)
    return [{"framework": k, "count": int(v)} for k, v in vc.items()]


def soc2_real_score(df):
    """
    Compute SOC2 pass rate DIRECTLY from Prowler rows where FRAMEWORK == 'SOC2'.
    This replaces the old hardcoded 44% (which had no source) with a real,
    reproducible number.
    """
    if df.empty or "FRAMEWORK" not in df.columns:
        return {"total": 0, "pass": 0, "fail": 0, "score_pct": 0.0, "formula": "no data"}
    soc2 = df[df["FRAMEWORK"] == "SOC2"]
    total = len(soc2)
    p = int((soc2["STATUS"] == "PASS").sum())
    f = int((soc2["STATUS"] == "FAIL").sum())
    score = pct(p, p + f) if (p + f) else 0.0
    return {
        "total": total,
        "pass": p,
        "fail": f,
        "score_pct": score,
        "formula": f"PASS / (PASS + FAIL) = {p} / {p + f} computed from FRAMEWORK=='SOC2' rows in prowler_combined.csv",
    }


# ---------------------------------------------------------------------------
# Module 2: AWS Config JSON + GDPR/ISO/PCI markdown reports
# ---------------------------------------------------------------------------

def parse_aws_config(root):
    path = os.path.join(root, "module2-automated-compliance", "reports", "aws-config-compliance.json")
    if not os.path.isfile(path):
        return [], None
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    rules = []
    for rule in data.get("ComplianceByConfigRules", []):
        rules.append({
            "rule": rule.get("ConfigRuleName"),
            "status": rule.get("Compliance", {}).get("ComplianceType"),
        })
    return rules, path


def parse_md_compliance_score(root, filename):
    path = os.path.join(root, "module2-automated-compliance", "reports", filename)
    if not os.path.isfile(path):
        return None, None
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"Overall\s+([\w\-]+)\s+Score:\s*(\d+)%", text)
    if m:
        return int(m.group(2)), path
    return None, path


# ---------------------------------------------------------------------------
# Module 3: risk / top risks / BIA / threat model
# ---------------------------------------------------------------------------

def parse_top_risks(root, n=4):
    path = os.path.join(root, "module3-risk-management", "output", "top_10_risks.csv")
    if not os.path.isfile(path):
        return [], None
    df = pd.read_csv(path)
    df = df.drop_duplicates(subset=["Finding"]).head(n)
    risks = []
    for _, row in df.iterrows():
        risks.append({
            "finding": str(row.get("Finding", ""))[:160],
            "severity": row.get("Risk Level"),
            "ale_usd": float(row.get("FAIR_ALE_USD", 0)),
        })
    return risks, path


def parse_total_ale(root):
    path = os.path.join(root, "module3-risk-management", "output", "top_10_risks.csv")
    if not os.path.isfile(path):
        return 0.0, path
    df = pd.read_csv(path)
    total = float(df["FAIR_ALE_USD"].sum())
    return total, path


def parse_bia(root, n=3):
    path = os.path.join(root, "module3-risk-management", "output", "bia_report.csv")
    if not os.path.isfile(path):
        return [], None
    df = pd.read_csv(path)
    df = df.sort_values("Financial Exposure", ascending=False).head(n)
    rows = []
    for _, row in df.iterrows():
        rows.append({
            "asset": row.get("Asset"),
            "criticality": row.get("Criticality"),
            "exposure_usd": float(row.get("Financial Exposure", 0)),
            "regulations": row.get("Regulations"),
        })
    return rows, path


def parse_threat_model(root, n=4):
    path = os.path.join(root, "module3-risk-management", "output", "threat_model_report.csv")
    if not os.path.isfile(path):
        return [], 0, None
    df = pd.read_csv(path)
    total_findings = int(len(df))
    # group by Service to build a small STRIDE summary similar to original dashboard
    top = (
        df.groupby("Service")["STRIDE_Threats"]
        .agg(lambda s: s.value_counts().idxmax())
        .reset_index()
        .head(n)
    )
    rows = [{"service": r["Service"], "stride": r["STRIDE_Threats"]} for _, r in top.iterrows()]
    return rows, total_findings, path


# ---------------------------------------------------------------------------
# Module 4: OPA / Sentinel / Ansible
# ---------------------------------------------------------------------------

def parse_opa_blocked(root):
    path = os.path.join(root, "module4-architecture-validation", "reports", "opa-validation-report.txt")
    if not os.path.isfile(path):
        return 0, path
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    blocked = len(re.findall(r"\bBLOCKED\b", text))
    return blocked, path


def parse_sentinel(root):
    path = os.path.join(root, "module4-architecture-validation", "reports", "sentinel-validation-report.txt")
    if not os.path.isfile(path):
        return {"fail": 0, "pass": 0}, path
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    fails = len(re.findall(r"^Fail\s*-\s*\S+\.sentinel", text, re.MULTILINE))
    passes = len(re.findall(r"^Pass\s*-\s*\S+\.sentinel", text, re.MULTILINE))
    return {"fail": fails, "pass": passes}, path


def parse_ansible_recap(root):
    path = os.path.join(root, "module4-architecture-validation", "reports", "ansible-hardening-report-ec2.txt")
    if not os.path.isfile(path):
        return None, path
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    m = re.search(
        r"ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)\s+skipped=(\d+)\s+rescued=(\d+)\s+ignored=(\d+)",
        text,
    )
    if not m:
        return None, path
    keys = ["ok", "changed", "unreachable", "failed", "skipped", "rescued", "ignored"]
    return {k: int(v) for k, v in zip(keys, m.groups())}, path


# ---------------------------------------------------------------------------
# Module 5: IAM — credential report + structured text findings
# ---------------------------------------------------------------------------

def parse_credential_report(root):
    path = os.path.join(root, "module5-iam-governance", "credential_report.csv")
    if not os.path.isfile(path):
        return None, path
    # keep_default_na=False so the literal string "N/A" used by the AWS credential
    # report is NOT silently converted to a pandas NaN float - we need to match on
    # the actual string the report writes for "never used the console password".
    df = pd.read_csv(path, keep_default_na=False, na_values=[])
    # drop the root account row for user-level MFA stats (matches the "9 users" framing
    # used throughout module5 reports)
    users = df[df["user"] != "<root_account>"].copy()
    no_mfa = int((users["mfa_active"].astype(str).str.lower() == "false").sum())
    total_users = int(len(users))
    # "ghost" = console password never used AND no access-key activity either
    # (matches the 7-user list in access_optimization_findings.txt - e.g. sec-user
    # never logged into the console but DOES have an actively-used access key,
    # so they are correctly excluded from "ghost").
    if users.empty:
        ghost = 0
    else:
        no_console_login = users["password_last_used"].astype(str) == "N/A"
        no_key_activity = users["access_key_1_last_used_date"].astype(str) == "N/A"
        ghost_mask = no_console_login & no_key_activity
        ghost = int(ghost_mask.sum())
    return {
        "total_users": total_users,
        "no_mfa": no_mfa,
        "ghost_accounts": ghost,
    }, path


def parse_azure_iam_findings(root):
    path = os.path.join(root, "module5-iam-governance", "azure_iam_findings.txt")
    if not os.path.isfile(path):
        return {"critical": 0, "high": 0}, path
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    crit = re.search(r"Critical findings:\s*(\d+)", text)
    high = re.search(r"High risk findings:\s*(\d+)", text)
    owner_subscription = len(re.findall(r"Role:\s*Owner\s*\n\s*Scope:\s*Entire subscription", text))
    contributor_subscription = len(re.findall(r"Role:\s*Contributor\s*\n\s*Scope:\s*Entire subscription", text))
    return {
        "critical": int(crit.group(1)) if crit else 0,
        "high": int(high.group(1)) if high else 0,
        "owner_at_subscription": owner_subscription,
        "contributor_at_subscription": contributor_subscription,
    }, path


def parse_privesc_findings(root):
    """Count CRITICAL privilege-escalation findings from remediation_report.txt"""
    path = os.path.join(root, "module5-iam-governance", "remediation_report.txt")
    if not os.path.isfile(path):
        return 0, path
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    m = re.search(r"SUMMARY:\s*(\d+)\s*user\(s\)\s*with escalation risks", text)
    return (int(m.group(1)) if m else 0), path


def compute_iam_scores(cred_stats, azure_stats, privesc_count):
    """
    Transparent, documented scoring formula (NOT hardcoded):

    AWS score   = 100
                  - 6  * users_without_mfa   (capped at 54)
                  - 15 * critical_privesc_findings (capped at 30)

    Azure score = 100
                  - 20 * owner_at_subscription_assignments (capped at 60)
                  - 8  * contributor_at_subscription_assignments (capped at 32)

    Combined    = average(AWS, Azure)

    All inputs are counts pulled directly from credential_report.csv and
    azure_iam_findings.txt - nothing here is a free-standing constant.
    """
    no_mfa = cred_stats["no_mfa"] if cred_stats else 0
    aws_score = 100 - min(no_mfa * 6, 54) - min(privesc_count * 15, 30)
    aws_score = max(aws_score, 0)

    owner_sub = azure_stats.get("owner_at_subscription", 0)
    contrib_sub = azure_stats.get("contributor_at_subscription", 0)
    azure_score = 100 - min(owner_sub * 20, 60) - min(contrib_sub * 8, 32)
    azure_score = max(azure_score, 0)

    combined = round((aws_score + azure_score) / 2)

    return {
        "aws_score": aws_score,
        "azure_score": azure_score,
        "combined_score": combined,
        "formula": (
            f"AWS = 100 - 6*{no_mfa}(no MFA, capped 54) - 15*{privesc_count}(privesc, capped 30) = {aws_score}; "
            f"Azure = 100 - 20*{owner_sub}(Owner@sub, capped 60) - 8*{contrib_sub}(Contributor@sub, capped 32) = {azure_score}; "
            f"Combined = avg = {combined}"
        ),
    }


# ---------------------------------------------------------------------------
# Trend history (append-only — gives requirement #iii real backing over time)
# ---------------------------------------------------------------------------

def update_trend_history(history_path, today_entry):
    history = []
    if os.path.isfile(history_path):
        with open(history_path, "r", encoding="utf-8") as f:
            try:
                history = json.load(f)
            except json.JSONDecodeError:
                history = []
    # avoid duplicate same-day entries (re-running pipeline same day updates, not duplicates)
    today_str = today_entry["date"]
    history = [h for h in history if h["date"] != today_str]
    history.append(today_entry)
    history.sort(key=lambda h: h["date"])
    with open(history_path, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)
    return history


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, help="Path to security-platform repo root")
    parser.add_argument("--out", default="metrics.json", help="Output metrics JSON path")
    parser.add_argument("--history", default="trend_history.json", help="Trend history JSON path")
    args = parser.parse_args()

    root = args.root
    sources_used = []

    print("[1/6] Combining Prowler compliance CSVs (Module 1)...")
    prowler_df, prowler_files = build_prowler_combined(root)
    sources_used.extend(prowler_files)
    prowler_stats = prowler_summary(prowler_df)
    coverage = framework_coverage(prowler_df)
    soc2 = soc2_real_score(prowler_df)
    print(f"   -> combined {len(prowler_files)} CSVs, {prowler_stats['total']} total checks")

    print("[2/6] Parsing Module 2 (AWS Config + GDPR/ISO/PCI reports)...")
    config_rules, config_path = parse_aws_config(root)
    if config_path:
        sources_used.append(config_path)
    gdpr_score, gdpr_path = parse_md_compliance_score(root, "gdpr-compliance-report.md")
    iso_score, iso_path = parse_md_compliance_score(root, "iso27001-compliance-report.md")
    pci_score, pci_path = parse_md_compliance_score(root, "pci-dss-compliance-report.md")
    for p in (gdpr_path, iso_path, pci_path):
        if p:
            sources_used.append(p)
    scores = [s for s in (gdpr_score, iso_score, pci_score, soc2["score_pct"]) if s is not None]
    avg_compliance = round(sum(scores) / len(scores), 1) if scores else 0.0

    print("[3/6] Parsing Module 3 (risk register, BIA, threat model)...")
    top_risks, top_risks_path = parse_top_risks(root)
    total_ale, _ = parse_total_ale(root)
    bia_rows, bia_path = parse_bia(root)
    stride_rows, threat_total, threat_path = parse_threat_model(root)
    for p in (top_risks_path, bia_path, threat_path):
        if p:
            sources_used.append(p)

    print("[4/6] Parsing Module 4 (OPA / Sentinel / Ansible)...")
    opa_blocked, opa_path = parse_opa_blocked(root)
    sentinel_stats, sentinel_path = parse_sentinel(root)
    ansible_recap, ansible_path = parse_ansible_recap(root)
    for p in (opa_path, sentinel_path, ansible_path):
        if p:
            sources_used.append(p)

    print("[5/6] Parsing Module 5 (IAM governance, credential report)...")
    cred_stats, cred_path = parse_credential_report(root)
    azure_stats, azure_path = parse_azure_iam_findings(root)
    privesc_count, privesc_path = parse_privesc_findings(root)
    for p in (cred_path, azure_path, privesc_path):
        if p:
            sources_used.append(p)
    iam_scores = compute_iam_scores(cred_stats, azure_stats, privesc_count)

    print("[6/6] Computing overall security score + updating trend history...")
    # Overall score: weighted blend across modules — documented, not arbitrary
    overall_score = round(
        0.35 * iam_scores["combined_score"]
        + 0.35 * avg_compliance
        + 0.30 * (100 - prowler_stats["fail_pct"])
    )

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    history = update_trend_history(
        args.history,
        {"date": today, "security_score": overall_score, "avg_compliance": avg_compliance},
    )

    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "generate_metrics.py",
        "sources_used": sorted(set(os.path.relpath(p, root) for p in sources_used if p)),
        "module1_module3_prowler": {
            "summary": prowler_stats,
            "framework_coverage": coverage,
        },
        "module2_compliance": {
            "gdpr_pct": gdpr_score,
            "iso27001_pct": iso_score,
            "pci_dss_pct": pci_score,
            "soc2_pct": soc2["score_pct"],
            "soc2_detail": soc2,
            "avg_compliance_pct": avg_compliance,
            "aws_config_rules": config_rules,
        },
        "module3_risk": {
            "top_risks": top_risks,
            "total_ale_usd": total_ale,
            "bia_top_assets": bia_rows,
            "stride_summary": stride_rows,
            "threat_model_total_findings": threat_total,
        },
        "module4_architecture": {
            "opa_blocked": opa_blocked,
            "sentinel": sentinel_stats,
            "ansible_recap": ansible_recap,
        },
        "module5_iam": {
            "credential_report": cred_stats,
            "azure_iam": azure_stats,
            "privilege_escalation_findings": privesc_count,
            "scores": iam_scores,
        },
        "overall_security_score": overall_score,
        "overall_score_formula": (
            f"0.35*IAM_combined({iam_scores['combined_score']}) + "
            f"0.35*avg_compliance({avg_compliance}) + "
            f"0.30*(100-prowler_fail_pct)({round(100 - prowler_stats['fail_pct'], 1)}) = {overall_score}"
        ),
        "trend_history": history,
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nDone. Wrote {args.out}")
    print(f"Sources used ({len(metrics['sources_used'])} files):")
    for s in metrics["sources_used"]:
        print(f"  - {s}")


if __name__ == "__main__":
    main()
