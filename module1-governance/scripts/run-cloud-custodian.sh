#!/bin/bash
# ================================================
# Cloud Custodian Policy Enforcement Script
# Author: Hussain
# Description: Runs Cloud Custodian policy-as-code
#              checks against AWS account
# Policies: s3-public-buckets, security-groups-open-ssh,
#           iam-users-no-mfa
# ================================================

echo "=== Cloud Custodian Policy Run ==="
echo "Running security policies against AWS account..."
custodian run \
  --output-dir module1-governance/cloud-custodian/output \
  module1-governance/cloud-custodian/policies.yml \
  --region eu-north-1

echo ""
echo "Policy run complete! Results saved to module1-governance/cloud-custodian/output/"
