import pandas as pd

# -----------------------------
# 1️⃣ Load combined Prowler data
# -----------------------------
df = pd.read_csv("/workspaces/security-platform/module3-risk/input/prowler_combined.csv")

# Clean column names
df.columns = df.columns.str.strip()

# Filter only failed controls
df = df[df["STATUS"] == "FAIL"]

print(f"Total FAILED findings: {len(df)}")

# -----------------------------
# 2️⃣ Control Criticality Mapping
# -----------------------------
control_criticality = {
    "CloudTrail": 0.9,
    "IAM Access Analyzer": 0.85,
    "Config": 0.8,
    "SecurityHub": 0.75,
    "Billing": 0.4
}

df["Criticality"] = df["REQUIREMENTS_ATTRIBUTES_SERVICE"].map(control_criticality).fillna(0.5)

# -----------------------------
# 3️⃣ Business Impact Mapping
# -----------------------------
impact_map = {
    "CloudTrail": 15000,
    "IAM Access Analyzer": 12000,
    "Config": 10000,
    "SecurityHub": 9000,
    "Billing": 3000
}

df["Impact"] = df["REQUIREMENTS_ATTRIBUTES_SERVICE"].map(impact_map).fillna(5000)

# -----------------------------
# 4️⃣ Risk Score Calculation
# -----------------------------
df["Risk Score"] = df["Criticality"] * df["Impact"]

# -----------------------------
# 5️⃣ Risk Level Classification
# -----------------------------
def risk_level(score):
    if score > 12000:
        return "Critical"
    elif score > 8000:
        return "High"
    elif score > 4000:
        return "Medium"
    else:
        return "Low"

df["Risk Level"] = df["Risk Score"].apply(risk_level)

# -----------------------------
# 6️⃣ Risk Treatment
# -----------------------------
def treatment(level):
    if level == "Critical":
        return "Fix Immediately"
    elif level == "High":
        return "Fix in 24 hours"
    elif level == "Medium":
        return "Monitor"
    else:
        return "Accept"

df["Treatment"] = df["Risk Level"].apply(treatment)

# -----------------------------
# 7️⃣ Rename for clarity
# -----------------------------
df.rename(columns={
    "REQUIREMENTS_DESCRIPTION": "Finding",
    "REQUIREMENTS_ATTRIBUTES_SERVICE": "Service"
}, inplace=True)

# -----------------------------
# 8️⃣ Final Output
# -----------------------------
df_final = df[[
    "ACCOUNTID",
    "REGION",
    "Service",
    "Finding",
    "STATUS",
    "Risk Score",
    "Risk Level",
    "Treatment"
]]

# Save full report
df_final.to_csv("../output/risk_report.csv", index=False)

# -----------------------------
# 9️⃣ Top 10 Risks
# -----------------------------
top10 = df_final.sort_values(by="Risk Score", ascending=False).head(10)
top10.to_csv("/workspaces/security-platform/module3-risk/output/top_10_risks.csv", index=False)

# -----------------------------
# 10️⃣ Total Risk Exposure
# -----------------------------
total_risk = df_final["Risk Score"].sum()

print("\n📊 Risk Summary")
print(f"Total Risk Exposure: ${total_risk}")
print(f"Top 10 risks saved successfully!")
