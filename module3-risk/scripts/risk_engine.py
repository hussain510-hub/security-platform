import pandas as pd
import os

# -----------------------------
# 1️⃣ Load combined Prowler + custom cloud risks data
# -----------------------------
input_file = "/workspaces/security-platform/module3-risk/input/prowler_combined.csv"
if not os.path.exists(input_file):
    print(f"❌ Input file not found: {input_file}")
    exit()

df = pd.read_csv(input_file)
df.columns = df.columns.str.strip()

# Filter only failed controls
df = df[df["STATUS"] == "FAIL"]
print(f"Total FAILED findings: {len(df)}")

# -----------------------------
# 2️⃣ Control Criticality Mapping
# -----------------------------
# Add more cloud services for broader coverage
control_criticality = {
    "CloudTrail": 0.9,
    "IAM Access Analyzer": 0.85,
    "Config": 0.8,
    "SecurityHub": 0.75,
    "Billing": 0.4,
    # Additional critical checks
    "EC2": 0.95,                  # e.g., public SSH ports
    "S3": 0.95,                   # e.g., public buckets
    "NSG": 0.9,                   # Azure network security groups misconfigs
    "AzureVM": 0.85,
    "AzureStorage": 0.9
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
    "Billing": 3000,
    # Additional cloud services
    "EC2": 20000,
    "S3": 18000,
    "NSG": 15000,
    "AzureVM": 15000,
    "AzureStorage": 17000
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
    if score > 15000:
        return "Critical"
    elif score > 10000:
        return "High"
    elif score > 5000:
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

# ─── FAIR ALE Score (simple version) ───────────────────────
# FAIR formula: ALE = TEF × Vulnerability × Loss Magnitude
# TEF = how many times per year this could happen
# Vulnerability = chance it succeeds (0–1)
# Loss Magnitude = financial damage if it does

fair_params = {
    "EC2":          {"tef": 6,   "vuln": 0.85, "loss": 500_000},
    "S3":           {"tef": 6,   "vuln": 0.85, "loss": 800_000},
    "NSG":          {"tef": 4,   "vuln": 0.75, "loss": 300_000},
    "AzureStorage": {"tef": 3,   "vuln": 0.70, "loss": 400_000},
    "AzureVM":      {"tef": 3,   "vuln": 0.70, "loss": 250_000},
    "CloudTrail":   {"tef": 2,   "vuln": 0.60, "loss": 150_000},
    "IAM Access Analyzer": {"tef": 4, "vuln": 0.80, "loss": 350_000},
    "Config":       {"tef": 2,   "vuln": 0.50, "loss": 100_000},
    "SecurityHub":  {"tef": 1.5, "vuln": 0.50, "loss":  90_000},
    "Billing":      {"tef": 1,   "vuln": 0.30, "loss":  30_000},
}

def calc_fair_ale(service):
    p = fair_params.get(service, {"tef": 1, "vuln": 0.40, "loss": 50_000})
    return round(p["tef"] * p["vuln"] * p["loss"], 2)

df["FAIR_ALE_USD"] = df["Service"].apply(calc_fair_ale)

# -----------------------------
# 8️⃣ Final Output
# -----------------------------
df_final = df[[
    "ACCOUNTID", "REGION", "Service", "Finding",
    "STATUS", "Risk Score", "Risk Level", "Treatment", "FAIR_ALE_USD"
]]

# Save full report
os.makedirs("../output", exist_ok=True)
df_final.to_csv("../output/risk_report.csv", index=False)

# -----------------------------
# 9️⃣ Top 10 Risks
# -----------------------------
top10 = df_final.sort_values(by="Risk Score", ascending=False).head(10)
top10.to_csv("../output/top_10_risks.csv", index=False)

# -----------------------------
# 10️⃣ Total Risk Exposure
# -----------------------------
total_risk = df_final["Risk Score"].sum()
print("\n📊 Risk Summary")
print(f"Total Risk Exposure: ${total_risk}")
print(f"Top 10 risks saved successfully!")
