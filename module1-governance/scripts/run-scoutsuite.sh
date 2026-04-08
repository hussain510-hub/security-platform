#!/bin/bash
# ================================================
# ScoutSuite Visual Security Dashboard Script
# Author: Hussain
# Description: Runs ScoutSuite to generate visual
#              HTML security dashboard for AWS
# Results: 351 total findings across 17 AWS services
#          Top issues: VPC (194), EC2 (115), CloudTrail (19)
# ================================================

echo "=== ScoutSuite AWS Scan ==="
echo "Generating visual security dashboard..."
scout aws \
  --report-dir module1-governance/aws/scoutsuite \
  --no-browser

echo ""
echo "Scan complete! To view the report:"
echo "cd module1-governance/aws/scoutsuite"
echo "python3 -m http.server 8000"
echo "Then open port 8000 in your browser"
