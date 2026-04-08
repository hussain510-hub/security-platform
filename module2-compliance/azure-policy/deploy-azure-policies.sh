#!/bin/bash
# ================================================
# Azure Policy Deployment Script
# Author: Hussain
# Description: Deploys compliance policies to Azure
#              subscription for GDPR, ISO27001, PCI-DSS
# Subscription: 4db9fc14-989b-40b7-be4d-5bde1c4d991a
# ================================================

SUBSCRIPTION_ID="4db9fc14-989b-40b7-be4d-5bde1c4d991a"
POLICY_DIR="module2-compliance/azure-policy"

echo "=== Verifying Azure Connection ==="
az account show

echo ""
echo "=== Step 1: Deploying Require Environment Tag Policy ==="
echo "Standard: ISO27001 - Asset Management (A.8.1)"
az policy definition create \
  --name "require-environment-tag" \
  --display-name "Require Environment Tag on all resources" \
  --description "Denies creation of resources without Environment tag - ISO27001 compliance" \
  --rules ${POLICY_DIR}/require-tags-policy.json \
  --mode All

echo ""
echo "=== Step 2: Deploying Allowed EU Locations Policy ==="
echo "Standard: GDPR - Data Residency (Article 44)"
az policy definition create \
  --name "allowed-eu-locations" \
  --display-name "Allow EU Locations Only" \
  --description "Restricts resource creation to EU regions only - GDPR compliance" \
  --rules ${POLICY_DIR}/allowed-locations-policy.json \
  --mode All

echo ""
echo "=== Step 3: Deploying Require HTTPS Storage Policy ==="
echo "Standard: PCI-DSS - Encrypt data in transit (Req 4)"
az policy definition create \
  --name "require-https-storage" \
  --display-name "Require HTTPS for Storage Accounts" \
  --description "Denies storage accounts without HTTPS only traffic - PCI-DSS compliance" \
  --rules ${POLICY_DIR}/require-https-storage.json \
  --mode All

echo ""
echo "=== Step 4: Assigning Policies to Subscription ==="
az policy assignment create \
  --name "enforce-environment-tag" \
  --display-name "Enforce Environment Tag" \
  --policy "require-environment-tag" \
  --scope "/subscriptions/${SUBSCRIPTION_ID}"

az policy assignment create \
  --name "enforce-eu-locations" \
  --display-name "Enforce EU Locations Only" \
  --policy "allowed-eu-locations" \
  --scope "/subscriptions/${SUBSCRIPTION_ID}"

az policy assignment create \
  --name "enforce-https-storage" \
  --display-name "Enforce HTTPS Storage" \
  --policy "require-https-storage" \
  --scope "/subscriptions/${SUBSCRIPTION_ID}"

echo ""
echo "=== Verifying All Policies Active ==="
az policy assignment list \
  --scope "/subscriptions/${SUBSCRIPTION_ID}" \
  --output table

echo ""
echo "Done! 3 compliance policies deployed and enforced."
