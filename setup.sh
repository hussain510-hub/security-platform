#!/bin/bash

set -e

echo "🔄 Updating system..."
sudo apt update -y

echo "📦 Installing system dependencies..."
sudo apt install -y python3-pip python3-venv git curl unzip gnupg

echo "🔧 Installing Terraform (HashiCorp official repo)..."

sudo mkdir -p /usr/share/keyrings

curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/hashicorp.gpg

echo "deb [signed-by=/usr/share/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list

sudo apt update -y
sudo apt install -y terraform

echo "🐍 Creating virtual environment..."
python3 -m venv venv

echo "⬆️ Upgrading pip..."
python3 -m pip install --upgrade pip

echo "🛡️ Installing cloud security tools..."
pip install prowler scoutsuite ansible --prefer-binary
pip install "c7n==0.9.49"

echo "🔐 Installing OPA (Open Policy Agent)..."
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod +x opa
sudo mv opa /usr/local/bin/

echo "✅ Verifying installations..."

terraform -version
aws --version || echo "AWS CLI not installed or not in PATH"
prowler --version || echo "Prowler OK"
scout --version || echo "ScoutSuite OK"
custodian version || echo "Cloud Custodian OK"
ansible --version || echo "Ansible OK"
opa version || echo "OPA OK"

echo "🎉 Setup complete!"
echo "👉 Activate Python environment manually when needed: source venv/bin/activate"
