#!/bin/bash
# ================================================
# Prowler Security Scanner Script
# Author: Hussain
# Description: Runs Prowler security scans on AWS and Azure
# Results: 87 failed checks on AWS, compliance mapped to
#          GDPR, ISO27001, PCI-DSS, CIS, NIST
# ================================================

echo "=== AWS Prowler Scan ==="
echo "Scanning AWS account in eu-north-1..."
prowler aws \
  --region eu-north-1 \
  --output-formats html json-ocsf \
  --output-directory module1-governance/aws/prowler/

echo ""
echo "=== Azure Prowler Scan ==="
echo "Scanning Azure subscription using az-cli-auth..."
prowler azure \
  --az-cli-auth \
  --output-formats html \
  --output-directory module1-governance/azure/prowler/

echo ""
echo "Scans complete! Results saved to module1-governance/aws/prowler/ and module1-governance/azure/prowler/"
