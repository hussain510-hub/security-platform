#!/bin/bash

echo "🚀 Post-create setup running..."

# Verify installs
python3 --version
terraform -version
aws --version
opa version

echo "✅ DevSecOps environment ready!"
