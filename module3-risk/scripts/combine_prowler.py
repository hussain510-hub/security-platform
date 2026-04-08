import pandas as pd
import os

# -----------------------------
# 1️⃣ Define paths to AWS and Azure compliance CSVs
# -----------------------------
aws_folder = "/workspaces/security-platform/module1-governance/aws/prowler/compliance"
azure_folder = "/workspaces/security-platform/module1-governance/azure/prowler/compliance"

all_files = []

# Loop through both AWS and Azure folders
for folder_path in [aws_folder, azure_folder]:
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".csv"):
                all_files.append(os.path.join(root, file))

if not all_files:
    print("❌ No CSV files found! Check folder paths.")
    exit()

df_list = []

for file_path in all_files:
    try:
        df = pd.read_csv(file_path, sep=";")  # Prowler uses semicolon separator
        if df.empty:
            print(f"⚠️ Skipping empty file: {file_path}")
            continue
        df["Source_File"] = os.path.basename(file_path)
        df_list.append(df)
    except pd.errors.EmptyDataError:
        print(f"⚠️ Skipping file with no data: {file_path}")
    except Exception as e:
        print(f"❌ Error reading {file_path}: {e}")

if not df_list:
    print("❌ No valid CSV files to combine!")
    exit()

# Combine all CSV files
combined_df = pd.concat(df_list, ignore_index=True)

# Clean column names
combined_df.columns = combined_df.columns.str.strip()

# Save combined file
output_path = "/workspaces/security-platform/module3-risk/input/prowler_combined.csv"
combined_df.to_csv(output_path, index=False)

print(f"✅ Combined {len(df_list)} files")
print(f"✅ Total findings: {len(combined_df)}")
