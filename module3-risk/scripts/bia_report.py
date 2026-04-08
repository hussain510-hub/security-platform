import csv

# Business Impact Analysis
# Links cloud assets to risk findings and calculates total exposure

assets = [
    {
        "asset": "AWS Production Account (eu-north-1)",
        "type": "Cloud Account",
        "criticality": "CRITICAL",
        "rto_hours": 2,
        "rpo_hours": 1,
        "revenue_per_hour": 30_000,
        "linked_services": ["EC2", "CloudTrail", "Config"],
        "regulations": "SOC2, ISO27001",
    },
    {
        "asset": "Customer Data Storage (S3)",
        "type": "Storage",
        "criticality": "CRITICAL",
        "rto_hours": 1,
        "rpo_hours": 0.5,
        "revenue_per_hour": 50_000,
        "linked_services": ["S3"],
        "regulations": "GDPR, PCI-DSS",
    },
    {
        "asset": "Azure Virtual Machines",
        "type": "Compute",
        "criticality": "HIGH",
        "rto_hours": 4,
        "rpo_hours": 2,
        "revenue_per_hour": 15_000,
        "linked_services": ["AzureVM", "NSG"],
        "regulations": "ISO27001",
    },
    {
        "asset": "Azure Storage (EU)",
        "type": "Storage",
        "criticality": "HIGH",
        "rto_hours": 4,
        "rpo_hours": 1,
        "revenue_per_hour": 10_000,
        "linked_services": ["AzureStorage"],
        "regulations": "GDPR",
    },
    {
        "asset": "Security Monitoring Platform",
        "type": "Security Tool",
        "criticality": "MEDIUM",
        "rto_hours": 8,
        "rpo_hours": 4,
        "revenue_per_hour": 5_000,
        "linked_services": ["SecurityHub", "IAM Access Analyzer"],
        "regulations": "SOC2",
    },
]

# Max outage hours before business continuity kicks in
max_outage = {"CRITICAL": 24, "HIGH": 72, "MEDIUM": 168, "LOW": 720}

results = []
for a in assets:
    outage_hrs = max_outage[a["criticality"]]
    financial_impact = a["revenue_per_hour"] * outage_hrs
    results.append({
        "Asset":             a["asset"],
        "Type":              a["type"],
        "Criticality":       a["criticality"],
        "RTO (hrs)":         a["rto_hours"],
        "RPO (hrs)":         a["rpo_hours"],
        "Revenue/hr (USD)":  a["revenue_per_hour"],
        "Max Outage (hrs)":  outage_hrs,
        "Financial Exposure":financial_impact,
        "Linked Services":   ", ".join(a["linked_services"]),
        "Regulations":       a["regulations"],
        "Recommendation": (
            "Activate incident response immediately"  if a["criticality"] == "CRITICAL" else
            "Escalate to CISO within 24 hours"        if a["criticality"] == "HIGH"     else
            "Review in next sprint"
        )
    })

# Sort by exposure
results.sort(key=lambda x: x["Financial Exposure"], reverse=True)

# Print summary
print("\nBusiness Impact Analysis Report")
print("="*60)
total = 0
for r in results:
    print(f"{r['Asset'][:40]:<40} {r['Criticality']:<10} ${r['Financial Exposure']:>12,.0f}")
    total += r["Financial Exposure"]
print("-"*60)
print(f"{'TOTAL ENTERPRISE EXPOSURE':<40} {'':10} ${total:>12,.0f}")

# Export CSV
with open("/workspaces/security-platform/module3-risk/output/bia_report.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=results[0].keys())
    w.writeheader()
    w.writerows(results)

print("\nbia_report.csv saved to output/")
