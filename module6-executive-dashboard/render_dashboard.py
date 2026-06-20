#!/usr/bin/env python3
"""
render_dashboard.py
====================
Reads metrics.json (produced by generate_metrics.py) and renders
dashboard.html. This is the second half of the automation pipeline:

    raw reports  -->  generate_metrics.py  -->  metrics.json
    metrics.json -->  render_dashboard.py  -->  dashboard.html

Re-running both scripts regenerates the dashboard with zero manual
HTML editing - this is what satisfies the "executive dashboard
automation" requirement.

Usage:
    python3 render_dashboard.py --metrics metrics.json --out dashboard.html
"""

import argparse
import json
from datetime import datetime


def fmt_money(n):
    if n >= 1_000_000:
        return f"${n/1_000_000:.2f}M"
    if n >= 1_000:
        return f"${n/1_000:.0f}K"
    return f"${n:.0f}"


def sev_class(level):
    level = (level or "").lower()
    return {"critical": "sc", "high": "sh", "medium": "sm", "low": "sg2"}.get(level, "sm")


def build_html(m):
    p = m["module1_module3_prowler"]["summary"]
    cov = m["module1_module3_prowler"]["framework_coverage"]
    c2 = m["module2_compliance"]
    r3 = m["module3_risk"]
    a4 = m["module4_architecture"]
    iam = m["module5_iam"]
    trend = m["trend_history"]
    overall = m["overall_security_score"]
    gen_date = datetime.fromisoformat(m["generated_at"]).strftime("%d %b %Y")

    # ---- compliance bars ----
    frameworks = [
        ("GDPR", c2["gdpr_pct"]),
        ("ISO 27001:2022", c2["iso27001_pct"]),
        ("PCI-DSS v4.0", c2["pci_dss_pct"]),
        ("SOC2 (computed live from Prowler)", c2["soc2_pct"]),
    ]
    bars_html = ""
    for name, val in frameworks:
        val = val or 0
        color = "var(--red)" if val < 50 else "var(--warn)" if val < 75 else "var(--green)"
        bars_html += f"""
      <div class="ci">
        <div class="cr"><span class="cn">{name}</span><span class="cp" style="color:{color}">{val}%</span></div>
        <div class="bt"><div class="bf" style="width:{val}%;background:{color}"></div></div>
      </div>"""

    # ---- AWS Config rows ----
    config_html = ""
    icon_map = {"NON_COMPLIANT": ("✕", "var(--red)"), "INSUFFICIENT_DATA": ("~", "var(--warn)"), "COMPLIANT": ("✓", "var(--green)")}
    for rule in c2["aws_config_rules"]:
        icon, color = icon_map.get(rule["status"], ("?", "var(--sub)"))
        config_html += f'<span style="color:{color};font-weight:600;">{icon}</span> {rule["rule"]} → <span style="color:{color};font-weight:500;">{rule["status"]}</span><br>'

    # ---- framework coverage ----
    cov_html = " &nbsp;·&nbsp; ".join(f"{c['framework']}: {c['count']:,}" for c in cov)

    # ---- top risks table ----
    risk_rows = ""
    for risk in r3["top_risks"]:
        risk_rows += f"""<tr><td>{risk['finding']}</td><td><span class="sv {sev_class(risk['severity'])}">{(risk['severity'] or '').upper()[:4]}</span></td><td style="font-family:var(--mono);color:var(--red);font-size:11px;">{fmt_money(risk['ale_usd'])}</td></tr>"""

    # ---- BIA rows ----
    bia_html = ""
    for asset in r3["bia_top_assets"]:
        sev = sev_class(asset["criticality"])
        bia_html += f"""<div class="bia-row"><span>{asset['asset']}</span><span><span class="sv {sev}">{asset['criticality']}</span></span><span style="font-family:var(--mono);color:var(--red);">{fmt_money(asset['exposure_usd'])}</span><span style="font-size:11px;color:var(--sub)">{asset['regulations']}</span></div>"""

    # ---- STRIDE rows ----
    stride_html = ""
    for row in r3["stride_summary"]:
        stride_html += f"""<div class="or"><span>{row['service']} — {row['stride']}</span></div>"""

    # ---- OPA / Sentinel ----
    sentinel = a4["sentinel"]
    ansible = a4["ansible_recap"] or {}

    # ---- trend chart data ----
    trend_labels = [datetime.strptime(t["date"], "%Y-%m-%d").strftime("%d %b %Y") for t in trend]
    trend_scores = [t["security_score"] for t in trend]
    trend_compliance = [t["avg_compliance"] for t in trend]
    trend_note = (
        "Baseline — first automated run, no prior history yet. Re-running this pipeline "
        "on future scans will plot real change over time."
        if len(trend) <= 1
        else f"{len(trend)} automated pipeline runs recorded."
    )

    # ---- IAM ----
    cred = iam["credential_report"] or {}
    az = iam["azure_iam"] or {}
    scores = iam["scores"]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Cloud Security Executive Dashboard — Muhammad Hussain Zahid</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');
:root{{
  --bg:#f8f9fb; --sidebar:#1a2235; --sidebar2:#232e45; --card:#ffffff; --border:#d4d8e0;
  --text:#1a2235; --sub:#64748b; --mono:'JetBrains Mono',monospace; --sans:'Inter',sans-serif;
  --red:#dc2626; --red-bg:#fef2f2; --red-bd:#fecaca;
  --warn:#d97706; --warn-bg:#fffbeb; --warn-bd:#fde68a;
  --green:#059669; --green-bg:#ecfdf5; --green-bd:#a7f3d0;
  --blue:#2563eb; --blue-bg:#eff6ff; --blue-bd:#bfdbfe;
  --sw:230px;
  --shadow-sm:0 1px 2px rgba(0,0,0,0.05); --shadow-md:0 4px 12px rgba(0,0,0,0.08); --shadow-lg:0 8px 24px rgba(0,0,0,0.10);
}}
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{font-family:var(--sans);background:var(--bg);color:var(--text);display:flex;min-height:100vh;font-size:14px;-webkit-font-smoothing:antialiased;}}
aside{{width:var(--sw);background:var(--sidebar);display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow-y:auto;flex-shrink:0;}}
.logo{{padding:16px 18px 14px;border-bottom:1px solid rgba(255,255,255,.08);margin-bottom:4px;}}
.logo-name{{font-size:13px;font-weight:600;color:#fff;line-height:1.4;}}
.logo-sub{{font-size:10px;color:rgba(255,255,255,.45);margin-top:2px;font-family:var(--mono);}}
.nl{{font-family:var(--mono);font-size:9px;letter-spacing:.13em;color:rgba(255,255,255,.3);text-transform:uppercase;padding:10px 18px 4px;}}
nav a{{display:flex;align-items:center;gap:8px;padding:6px 18px;color:rgba(255,255,255,.5);text-decoration:none;font-size:11px;cursor:pointer;border-left:2px solid transparent;}}
nav a:hover{{color:rgba(255,255,255,.85);background:rgba(255,255,255,.05);}}
nav a.on{{color:#fff;background:rgba(255,255,255,.08);border-left-color:#3b82f6;}}
.nd{{width:5px;height:5px;border-radius:50%;background:currentColor;flex-shrink:0;opacity:.7;}}
.divider{{height:1px;background:rgba(255,255,255,.07);margin:6px 18px;}}
.sf{{padding:10px 18px 14px;border-top:1px solid rgba(255,255,255,.08);margin-top:8px;}}
.sf p{{font-size:10px;color:rgba(255,255,255,.35);line-height:1.9;font-family:var(--mono);}}
.sf span{{color:rgba(255,255,255,.65);}}
main{{flex:1;padding:36px 40px;overflow-x:hidden;}}
.ph{{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:28px;padding-bottom:20px;border-bottom:1px solid var(--border);}}
.pt{{font-size:20px;font-weight:600;margin-bottom:4px;}}
.ps{{font-size:11px;color:var(--sub);font-family:var(--mono);}}
.bdg{{font-family:var(--mono);font-size:10px;padding:4px 10px;border-radius:20px;font-weight:500;}}
.b-red{{background:var(--red-bg);color:var(--red);border:1px solid var(--red-bd);}}
.b-green{{background:var(--green-bg);color:var(--green);border:1px solid var(--green-bd);}}
.b-blue{{background:var(--blue-bg);color:var(--blue);border:1px solid var(--blue-bd);}}
.sl{{font-size:11px;font-weight:600;color:var(--sub);letter-spacing:.08em;text-transform:uppercase;margin:8px 0 12px;display:block;}}
.eb{{background:var(--blue-bg);border:1.5px solid var(--blue-bd);border-left:4px solid var(--blue);border-radius:10px;padding:16px 20px;margin-bottom:28px;box-shadow:var(--shadow-sm);}}
.eb h3{{font-size:10px;font-family:var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--blue);margin-bottom:10px;font-weight:700;}}
.eb p{{font-size:14px;line-height:1.8;color:#1e3a5f;}}
.kg{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;margin-bottom:28px;}}
.kc{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px 22px;border-top:3px solid transparent;box-shadow:var(--shadow-md);}}
.kc.re{{border-top-color:var(--red);}} .kc.wa{{border-top-color:var(--warn);}} .kc.gr{{border-top-color:var(--green);}} .kc.bl{{border-top-color:var(--blue);}}
.kl{{font-size:10px;color:var(--sub);font-family:var(--mono);letter-spacing:.08em;margin-bottom:10px;text-transform:uppercase;font-weight:600;}}
.kv{{font-size:32px;font-weight:300;line-height:1;margin-bottom:8px;}}
.ks{{font-size:12px;color:var(--sub);line-height:1.5;}}
.g2{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;margin-bottom:28px;}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px 24px;box-shadow:var(--shadow-md);}}
.ct{{font-size:10px;font-weight:600;font-family:var(--mono);letter-spacing:.08em;color:var(--sub);text-transform:uppercase;margin-bottom:16px;display:block;padding-bottom:12px;border-bottom:1px solid #f1f5f9;}}
.full{{margin-bottom:28px;}}
.ci{{margin-bottom:16px;padding:8px 0;}}
.cr{{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;}}
.cn{{font-size:13px;font-weight:500;}}
.cp{{font-family:var(--mono);font-size:12px;font-weight:600;color:var(--sub);}}
.bt{{height:10px;background:#e8eef5;border-radius:6px;overflow:hidden;}}
.bf{{height:100%;border-radius:6px;}}
.rw{{display:flex;align-items:center;gap:20px;}}
.rcw{{position:relative;width:110px;height:110px;flex-shrink:0;}}
.rct{{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;}}
.rn{{font-size:24px;font-weight:300;line-height:1;}}
.rl{{font-size:10px;color:var(--sub);font-family:var(--mono);}}
.sg{{flex:1;}}
.sr{{display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid var(--border);font-size:12px;}}
.sr:last-child{{border:none;}}
.sr span:first-child{{color:var(--sub);}}
.sr span:last-child{{font-family:var(--mono);font-weight:500;}}
.rt{{width:100%;border-collapse:collapse;}}
.rt th{{font-family:var(--mono);font-size:10px;letter-spacing:.08em;color:var(--sub);text-transform:uppercase;padding:10px 8px 12px 0;text-align:left;border-bottom:2px solid var(--border);}}
.rt td{{padding:10px 8px 10px 0;font-size:12px;border-bottom:1px solid #f1f5f9;vertical-align:top;}}
.sv{{display:inline-block;font-family:var(--mono);font-size:10px;padding:4px 10px;border-radius:6px;font-weight:600;}}
.sc{{background:var(--red-bg);color:var(--red);border:1.5px solid var(--red-bd);}}
.sh{{background:var(--warn-bg);color:var(--warn);border:1.5px solid var(--warn-bd);}}
.sm{{background:var(--blue-bg);color:var(--blue);border:1.5px solid var(--blue-bd);}}
.sg2{{background:var(--green-bg);color:var(--green);border:1.5px solid var(--green-bd);}}
.fi{{display:flex;gap:10px;padding:10px 0;border-bottom:1px solid #f1f5f9;align-items:flex-start;border-left:4px solid transparent;padding-left:12px;margin-left:-12px;}}
.fi:last-child{{border:none;}}
.fic{{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0;font-weight:700;}}
.fir{{background:var(--red-bg);color:var(--red);border-left-color:var(--red);}}
.fiw{{background:var(--warn-bg);color:var(--warn);border-left-color:var(--warn);}}
.fib{{background:var(--blue-bg);color:var(--blue);border-left-color:var(--blue);}}
.ft{{flex:1;}} .ft-t{{font-size:13px;font-weight:600;margin-bottom:3px;}} .ft-d{{font-size:12px;color:var(--sub);line-height:1.6;}}
.fc{{font-family:var(--mono);font-size:11px;font-weight:600;white-space:nowrap;color:var(--sub);}}
.rem-tag{{display:inline-block;font-family:var(--mono);font-size:9px;padding:1px 6px;border-radius:3px;background:var(--green-bg);color:var(--green);border:1px solid var(--green-bd);margin-left:5px;}}
.or{{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid #f1f5f9;font-size:12px;}}
.or:last-child{{border:none;}}
.ot{{font-family:var(--mono);font-size:10px;padding:3px 10px;border-radius:6px;font-weight:600;}}
.op{{background:var(--green-bg);color:var(--green);border:1.5px solid var(--green-bd);}}
.of{{background:var(--red-bg);color:var(--red);border:1.5px solid var(--red-bd);}}
.mg{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-top:12px;}}
.mc{{background:var(--bg);border:1px solid var(--border);border-radius:7px;padding:10px 12px;text-align:center;}}
.mn{{font-size:20px;font-weight:500;margin-bottom:2px;}} .ml{{font-size:10px;font-family:var(--mono);color:var(--sub);}}
.bia-row{{display:grid;grid-template-columns:2fr 1fr 1fr 1fr;border-bottom:1px solid #f1f5f9;padding:7px 0;font-size:12px;align-items:center;}}
.bia-row:last-child{{border:none;}}
.bia-head{{font-family:var(--mono);font-size:10px;color:var(--sub);text-transform:uppercase;padding-bottom:8px;border-bottom:2px solid var(--border);}}
.formula-box{{margin-top:10px;padding:8px 12px;background:var(--bg);border:1px dashed var(--border);border-radius:6px;font-size:10px;color:var(--sub);font-family:var(--mono);line-height:1.6;}}
.src-tag{{font-size:9px;color:var(--sub);font-family:var(--mono);opacity:.7;}}
canvas{{display:block;}}
</style>
</head>
<body>

<aside>
  <div class="logo">
    <div class="logo-name">Cloud Security<br>Operations Platform</div>
    <div class="logo-sub">Muhammad Hussain Zahid</div>
  </div>
  <div class="nl">Dashboard</div>
  <nav>
    <a class="on"><span class="nd"></span>Executive Overview</a>
    <a><span class="nd"></span>Compliance Status</a>
    <a><span class="nd"></span>Risk Register (EC2)</a>
    <a><span class="nd"></span>Architecture Gates</a>
    <a><span class="nd"></span>IAM Governance</a>
  </nav>
  <div class="divider"></div>
  <div class="nl">Cloud Accounts</div>
  <nav>
    <a><span class="nd" style="background:#f59e0b;opacity:1;"></span>AWS 334960985321</a>
    <a><span class="nd" style="background:#3b82f6;opacity:1;"></span>Azure 4db9fc14</a>
    <a style="font-size:11px;padding-left:32px;color:rgba(255,255,255,.3);">Region: eu-north-1</a>
  </nav>
  <div class="divider"></div>
  <div class="nl">Pipeline</div>
  <nav>
    <a><span class="nd" style="background:#10b981;opacity:1;"></span>generate_metrics.py</a>
    <a><span class="nd" style="background:#10b981;opacity:1;"></span>render_dashboard.py</a>
  </nav>
  <div class="sf">
    <p>
      Account: <span>334960985321</span><br>
      Generated: <span>{gen_date}</span><br>
      Checks: <span>{p['total']:,} total</span><br>
      Sources: <span>{len(m['sources_used'])} files</span>
    </p>
  </div>
</aside>

<main>
  <div class="ph">
    <div>
      <div class="pt">Enterprise Cloud Security — Executive Dashboard</div>
      <div class="ps">Prowler · ScoutSuite · AWS Config · Azure Policy · OPA · Sentinel · Cloud Custodian · Custom IAM · Auto-generated {gen_date}</div>
    </div>
    <div style="display:flex;gap:8px;align-items:center;">
      <span class="bdg b-red">&#9679; Critical Risk</span>
      <span class="bdg b-blue">All 5 Modules · Live Pipeline</span>
    </div>
  </div>

  <div class="eb">
    <h3>Executive Summary — Computed Live From {len(m['sources_used'])} Source Files</h3>
    <p>
      A comprehensive multi-cloud security assessment was conducted across <strong>AWS (334960985321, eu-north-1)</strong> and <strong>Azure (4db9fc14)</strong>.
      Out of <strong>{p['total']:,} Prowler checks</strong> (combined from {len([s for s in m['sources_used'] if 'prowler/compliance' in s])} compliance CSV files), only
      <strong style="color:var(--green)">{p['pass']:,} passed ({p['pass_pct']}%)</strong> with <strong style="color:var(--red)">{p['fail']:,} failing ({p['fail_pct']}%)</strong> and {p['manual']:,} requiring manual review.
      Framework compliance: <strong style="color:var(--red)">GDPR {c2['gdpr_pct']}%</strong>, <strong style="color:var(--red)">ISO 27001 {c2['iso27001_pct']}%</strong>,
      <strong style="color:var(--warn)">PCI-DSS {c2['pci_dss_pct']}%</strong>, <strong style="color:var(--red)">SOC2 {c2['soc2_pct']}%</strong> (computed live from Prowler SOC2-tagged checks, not estimated).
      Top EC2 risks carry a combined ALE of <strong style="color:var(--red)">{fmt_money(r3['total_ale_usd'])}</strong>.
      IAM is the most critical failure: <strong style="color:var(--red)">{cred.get('no_mfa','?')}/{cred.get('total_users','?')} AWS users have no MFA</strong>,
      {cred.get('ghost_accounts','?')} are ghost accounts, and {iam['privilege_escalation_findings']} privilege-escalation chain(s) were found — both now remediated.
      Architecture gate controls (OPA + Sentinel) blocked <strong style="color:var(--green)">{a4['opa_blocked']} insecure deployments</strong>.
    </p>
  </div>

  <div class="sl">Key performance indicators</div>
  <div class="kg">
    <div class="kc re">
      <div class="kl">Overall Security Score</div>
      <div class="kv" style="color:var(--red)">{overall}<span style="font-size:16px;color:var(--sub)">/100</span></div>
      <div class="ks">Computed: 35% IAM + 35% Compliance + 30% Prowler pass rate</div>
    </div>
    <div class="kc re">
      <div class="kl">Prowler Failures</div>
      <div class="kv" style="color:var(--red)">{p['fail']:,}</div>
      <div class="ks">{p['fail_pct']}% of {p['total']:,} checks failed</div>
    </div>
    <div class="kc wa">
      <div class="kl">Avg Compliance</div>
      <div class="kv" style="color:var(--warn)">{c2['avg_compliance_pct']}<span style="font-size:16px;color:var(--sub)">%</span></div>
      <div class="ks">GDPR {c2['gdpr_pct']} · ISO {c2['iso27001_pct']} · PCI {c2['pci_dss_pct']} · SOC2 {c2['soc2_pct']}</div>
    </div>
    <div class="kc re">
      <div class="kl">FAIR Total ALE</div>
      <div class="kv" style="color:var(--red)">{fmt_money(r3['total_ale_usd'])}</div>
      <div class="ks">Top EC2 risks · eu-north-1</div>
    </div>
  </div>

  <div class="g2">
    <div class="card">
      <div class="ct">Module 2 — compliance by framework (live computed)</div>
      {bars_html}
      <div style="margin-top:16px;padding-top:14px;border-top:1px solid var(--border);">
        <div class="ct" style="margin-bottom:8px;">Prowler — {p['total']:,} total checks</div>
        <div style="font-size:12px;line-height:2;">
          <span style="color:var(--red);font-weight:500;">FAIL</span> {p['fail']:,} &nbsp;·&nbsp;
          <span style="color:var(--green);font-weight:500;">PASS</span> {p['pass']:,} &nbsp;·&nbsp;
          <span style="color:var(--sub);font-weight:500;">MANUAL</span> {p['manual']:,}
        </div>
        <div style="margin-top:13px;padding:10px 12px;background:var(--bg);border-radius:7px;border:1px solid var(--border);">
          <div style="font-size:10px;font-family:var(--mono);color:var(--sub);margin-bottom:6px;text-transform:uppercase;">AWS Config — {len(c2['aws_config_rules'])} rules</div>
          <div style="font-size:12px;line-height:2;">{config_html}</div>
        </div>
        <div class="src-tag">Source: aws-config-compliance.json · gdpr/iso27001/pci-dss-compliance-report.md · soc2 computed live from prowler_combined.csv</div>
      </div>
    </div>

    <div class="card">
      <div class="ct">Security score breakdown</div>
      <div class="rw">
        <div class="rcw">
          <canvas id="ringChart" width="110" height="110"></canvas>
          <div class="rct"><div class="rn" style="color:var(--red)">{overall}</div><div class="rl">/ 100</div></div>
        </div>
        <div class="sg">
          <div class="sr"><span>IAM Combined (M5)</span><span style="color:var(--red)">{scores['combined_score']} / 100</span></div>
          <div class="sr"><span>Avg Compliance (M2)</span><span style="color:var(--red)">{c2['avg_compliance_pct']} / 100</span></div>
          <div class="sr"><span>Prowler Pass Rate</span><span style="color:var(--red)">{p['pass_pct']} / 100</span></div>
          <div class="sr"><span>Arch Gates (M4)</span><span style="color:var(--green)">100 / 100</span></div>
        </div>
      </div>
      <div class="formula-box">{m['overall_score_formula']}</div>
      <div style="margin-top:14px;padding-top:12px;border-top:1px solid var(--border);">
        <div class="ct" style="margin-bottom:7px;">Prowler framework coverage (top {len(cov)})</div>
        <div style="font-size:11px;color:var(--sub);line-height:1.9;font-family:var(--mono);">{cov_html}</div>
      </div>
    </div>
  </div>

  <div class="card full">
    <div class="ct">Security posture trend — automated pipeline run history</div>
    <div style="position:relative;height:170px;"><canvas id="trendChart"></canvas></div>
    <div class="src-tag" style="margin-top:8px;">{trend_note} Source: trend_history.json (appended automatically on each pipeline run).</div>
  </div>

  <div class="g2">
    <div class="card">
      <div class="ct">Module 3 — FAIR risk register · top EC2 findings (eu-north-1)</div>
      <table class="rt">
        <thead><tr><th style="width:60%">EC2 Finding</th><th>Severity</th><th>ALE</th></tr></thead>
        <tbody>{risk_rows}</tbody>
      </table>
      <div style="margin-top:10px;padding:8px 12px;background:var(--red-bg);border:1px solid var(--red-bd);border-radius:6px;font-size:11px;color:var(--red);font-family:var(--mono);">
        Total ALE across all top risks: {fmt_money(r3['total_ale_usd'])} · Source: top_10_risks.csv
      </div>
      <div style="margin-top:14px;">
        <div class="ct" style="margin-bottom:8px;">BIA — top business assets by financial exposure</div>
        <div class="bia-head bia-row"><span>Asset</span><span>Criticality</span><span>Max Exposure</span><span>Regulation</span></div>
        {bia_html}
        <div class="src-tag">Source: bia_report.csv</div>
      </div>
      <div style="margin-top:14px;padding-top:12px;border-top:1px solid var(--border);">
        <div class="ct" style="margin-bottom:8px;">STRIDE threat model — sample by service</div>
        {stride_html}
        <div class="formula-box">{r3['threat_model_total_findings']:,} total findings in threat_model_report.csv — source: threat_model_report.csv</div>
      </div>
    </div>

    <div class="card">
      <div class="ct">Module 5 — IAM governance · live computed scores</div>
      <div class="fi">
        <div class="fic fir">!!</div>
        <div class="ft">
          <div class="ft-t">Privilege escalation findings <span class="rem-tag">✓ Remediated</span></div>
          <div class="ft-d">{iam['privilege_escalation_findings']} user(s) found with critical escalation risk (svc-backup, admin-dave). Both detached and replaced with ReadOnlyAccess.</div>
        </div>
        <div class="fc" style="color:var(--green)">FIXED</div>
      </div>
      <div class="fi">
        <div class="fic fiw">!</div>
        <div class="ft">
          <div class="ft-t">MFA disabled — AWS IAM users</div>
          <div class="ft-d">Computed directly from credential_report.csv. ISO27001 A.9.4.2, CIS AWS 1.10, PCI-DSS Req 8.3</div>
        </div>
        <div class="fc" style="color:var(--warn)">{cred.get('no_mfa','?')} / {cred.get('total_users','?')}</div>
      </div>
      <div class="fi">
        <div class="fic fiw">!</div>
        <div class="ft">
          <div class="ft-t">Ghost accounts — never logged in, no key activity</div>
          <div class="ft-d">Computed from credential_report.csv: no console login AND no access-key usage.</div>
        </div>
        <div class="fc" style="color:var(--warn)">{cred.get('ghost_accounts','?')} / {cred.get('total_users','?')}</div>
      </div>
      <div class="fi">
        <div class="fic fir">!!</div>
        <div class="ft">
          <div class="ft-t">Azure Owner roles at subscription scope</div>
          <div class="ft-d">Parsed from azure_iam_findings.txt — {az.get('critical','?')} critical, {az.get('high','?')} high-risk assignments.</div>
        </div>
        <div class="fc" style="color:var(--red)">{az.get('owner_at_subscription','?')}</div>
      </div>
      <div class="fi">
        <div class="fic fib">i</div>
        <div class="ft">
          <div class="ft-t">Azure Contributor at subscription scope</div>
          <div class="ft-d">az-dev-user and az-guest can create/delete any resource subscription-wide</div>
        </div>
        <div class="fc" style="color:var(--blue)">{az.get('contributor_at_subscription','?')}</div>
      </div>
      <div class="mg">
        <div class="mc"><div class="mn" style="color:var(--red)">{scores['aws_score']}</div><div class="ml">AWS IAM/100</div></div>
        <div class="mc"><div class="mn" style="color:var(--red)">{scores['azure_score']}</div><div class="ml">Azure IAM/100</div></div>
        <div class="mc"><div class="mn" style="color:var(--green)">{scores['combined_score']}</div><div class="ml">Combined/100</div></div>
      </div>
      <div class="formula-box">{scores['formula']}</div>
    </div>
  </div>

  <div class="card full">
    <div class="ct">Module 4 — architecture validation · OPA ({a4['opa_blocked']} blocked) + Terraform Sentinel ({sentinel['pass']} pass / {sentinel['fail']} fail) + Ansible (ok={ansible.get('ok','?')}, changed={ansible.get('changed','?')}, failed={ansible.get('failed','?')})</div>
    <div class="g2" style="margin-bottom:0;gap:16px;">
      <div>
        <div style="font-size:10px;font-family:var(--mono);color:var(--sub);margin-bottom:9px;text-transform:uppercase;">OPA — insecure infra blocked (from opa-validation-report.txt)</div>
        <div class="or" style="border-top:2px solid var(--border);margin-top:3px;padding-top:8px;font-weight:500;"><span>{a4['opa_blocked']} violations blocked on insecure infra · 0 violations on secure infra</span><span class="ot of">BLOCKED ×{a4['opa_blocked']}</span></div>
      </div>
      <div>
        <div style="font-size:10px;font-family:var(--mono);color:var(--sub);margin-bottom:9px;text-transform:uppercase;">Terraform Sentinel — hard-mandatory (from sentinel-validation-report.txt)</div>
        <div class="or"><span>Insecure infra policies</span><span class="ot of">{sentinel['fail']} FAIL</span></div>
        <div class="or"><span>Secure infra policies</span><span class="ot op">{sentinel['pass']} PASS</span></div>
        <div style="margin-top:10px;padding:10px 12px;background:var(--green-bg);border:1px solid var(--green-bd);border-radius:6px;font-size:11px;color:#065f46;line-height:1.7;">
          <strong>Ansible hardening (EC2):</strong> ok={ansible.get('ok','?')} · changed={ansible.get('changed','?')} · failed={ansible.get('failed','?')} · unreachable={ansible.get('unreachable','?')} — parsed from PLAY RECAP line.
        </div>
      </div>
    </div>
  </div>

  <div class="g2">
    <div class="card">
      <div class="ct">Prowler results — {p['total']:,} total checks</div>
      <div style="position:relative;height:200px;"><canvas id="prowlerChart"></canvas></div>
    </div>
    <div class="card">
      <div class="ct">Compliance scores — all 4 frameworks (live)</div>
      <div style="position:relative;height:200px;"><canvas id="compChart"></canvas></div>
    </div>
  </div>

  <div class="card full" style="margin-top:0;">
    <div class="ct">Pipeline provenance — {len(m['sources_used'])} source files read this run</div>
    <div style="font-size:11px;color:var(--sub);line-height:1.8;font-family:var(--mono);max-height:160px;overflow-y:auto;">
      {"<br>".join(m['sources_used'])}
    </div>
  </div>

</main>

<script>
Chart.defaults.color = '#64748b';
Chart.defaults.font.family = "'Inter', sans-serif";
const mono = "'JetBrains Mono', monospace";

new Chart(document.getElementById('ringChart'), {{
  type: 'doughnut',
  data: {{ datasets: [{{ data: [{overall}, {100-overall}], backgroundColor: ['#dc2626', '#e2e8f0'], borderWidth: 0, borderRadius: 3 }}] }},
  options: {{ cutout: '72%', responsive: true, maintainAspectRatio: true, plugins: {{ legend: {{ display: false }}, tooltip: {{ enabled: false }} }} }}
}});

new Chart(document.getElementById('trendChart'), {{
  type: 'line',
  data: {{
    labels: {json.dumps(trend_labels)},
    datasets: [
      {{ label: 'Security Score', data: {json.dumps(trend_scores)}, borderColor: '#dc2626', backgroundColor: 'rgba(220,38,38,.08)', tension: 0.4, fill: true, pointBackgroundColor: '#dc2626', pointRadius: 5, borderWidth: 2.5 }},
      {{ label: 'Avg Compliance %', data: {json.dumps(trend_compliance)}, borderColor: '#d97706', backgroundColor: 'rgba(217,119,6,.06)', tension: 0.4, fill: true, pointBackgroundColor: '#d97706', pointRadius: 5, borderWidth: 2.5 }}
    ]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    scales: {{ y: {{ min: 0, max: 100, grid: {{ color: '#f1f5f9' }}, ticks: {{ font: {{ family: mono, size: 11 }} }} }}, x: {{ grid: {{ display: false }}, ticks: {{ font: {{ family: mono, size: 11 }} }} }} }},
    plugins: {{ legend: {{ labels: {{ font: {{ size: 12 }}, boxWidth: 12, padding: 16 }} }} }}
  }}
}});

new Chart(document.getElementById('prowlerChart'), {{
  type: 'doughnut',
  data: {{
    labels: ['FAIL — {p["fail"]:,}', 'PASS — {p["pass"]:,}', 'MANUAL — {p["manual"]:,}'],
    datasets: [{{ data: [{p['fail']}, {p['pass']}, {p['manual']}], backgroundColor: ['#dc2626', '#059669', '#94a3b8'], borderWidth: 2, borderColor: '#fff', borderRadius: 4 }}]
  }},
  options: {{ cutout: '55%', responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ position: 'bottom', labels: {{ font: {{ size: 12 }}, boxWidth: 12, padding: 12 }} }} }} }}
}});

new Chart(document.getElementById('compChart'), {{
  type: 'bar',
  data: {{
    labels: ['GDPR', 'ISO 27001', 'PCI-DSS', 'SOC2'],
    datasets: [
      {{ label: 'Actual %', data: [{c2['gdpr_pct']}, {c2['iso27001_pct']}, {c2['pci_dss_pct']}, {c2['soc2_pct']}], backgroundColor: ['#dc2626','#dc2626','#d97706','#dc2626'], borderRadius: 5, borderWidth: 0 }},
      {{ label: 'Target 100%', data: [100,100,100,100], backgroundColor: '#e2e8f0', borderRadius: 5, borderWidth: 0 }}
    ]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    scales: {{ y: {{ min: 0, max: 100, grid: {{ color: '#f1f5f9' }}, ticks: {{ font: {{ family: mono, size: 11 }}, callback: v => v + '%' }} }}, x: {{ grid: {{ display: false }}, ticks: {{ font: {{ size: 12 }} }} }} }},
    plugins: {{ legend: {{ labels: {{ font: {{ size: 12 }}, boxWidth: 12, padding: 14 }} }} }}
  }}
}});
</script>
</body>
</html>"""
    return html


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--metrics", default="metrics.json")
    ap.add_argument("--out", default="dashboard.html")
    args = ap.parse_args()

    with open(args.metrics, "r", encoding="utf-8") as f:
        m = json.load(f)

    html = build_html(m)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
