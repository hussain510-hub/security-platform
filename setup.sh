#!/bin/bash

echo "🚀 Starting DevSecOps setup..."

sudo apt-get update -y
sudo apt-get install -y python3-pip python3-dev build-essential curl unzip git jq

pip3 install --upgrade pip

pip3 install prowler scoutsuite ansible awscli azure-cli

pip3 install "c7n==0.9.38"

if ! command -v terraform &> /dev/null; then
  curl -fsSL https://releases.hashicorp.com/terraform/1.7.5/terraform_1.7.5_linux_amd64.zip -o tf.zip
  unzip tf.zip
  sudo mv terraform /usr/local/bin/
  rm tf.zip
fi

if ! command -v opa &> /dev/null; then
  curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
  chmod +x opa
  sudo mv opa /usr/local/bin/
fi

echo "✅ DevSecOps environment ready!"
