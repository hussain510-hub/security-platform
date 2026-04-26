#!/bin/bash

# OPA Test 1: S3 Security against insecure infrastructure - save to opa-validation-report.txt
opa eval --data module4-architecture/opa/policies/s3-security.rego --input module4-architecture/opa/test/insecure-input.json --format pretty "data.aws.s3.security.deny" >> module4-architecture/reports/opa-validation-report.txt

# OPA Test 2: Network Security against insecure infrastructure - save to opa-validation-report.txt
opa eval --data module4-architecture/opa/policies/security-group.rego --input module4-architecture/opa/test/insecure-input.json --format pretty "data.aws.security.network.deny" >> module4-architecture/reports/opa-validation-report.txt

# OPA Test 3: Encryption Policy against insecure infrastructure - save to opa-validation-report.txt
opa eval --data module4-architecture/opa/policies/encryption.rego --input module4-architecture/opa/test/insecure-input.json --format pretty "data.aws.encryption.deny" >> module4-architecture/reports/opa-validation-report.txt

# OPA Test 4: All policies against secure infrastructure (empty) - save to opa-validation-report.txt
opa eval --data module4-architecture/opa/policies/ --input module4-architecture/opa/test/secure-input.json --format pretty "data.aws.s3.security.deny" >> module4-architecture/reports/opa-validation-report.txt

# Sentinel Test 1: S3 policy against insecure plan FAIL - save to sentinel-validation-report.txt
sentinel apply -global "tfplan=$(cat module4-architecture/sentinel/test/insecure-tfplan.json)" module4-architecture/sentinel/policies/s3-security.sentinel >> module4-architecture/reports/sentinel-validation-report.txt

# Sentinel Test 2: Encryption policy against insecure plan FAIL - save to sentinel-validation-report.txt
sentinel apply -global "tfplan=$(cat module4-architecture/sentinel/test/insecure-tfplan.json)" module4-architecture/sentinel/policies/encryption.sentinel >> module4-architecture/reports/sentinel-validation-report.txt

# Sentinel Test 3: Network policy against insecure plan FAIL - save to sentinel-validation-report.txt
sentinel apply -global "tfplan=$(cat module4-architecture/sentinel/test/insecure-tfplan.json)" module4-architecture/sentinel/policies/network-security.sentinel >> module4-architecture/reports/sentinel-validation-report.txt

# Sentinel Test 4: S3 policy against secure plan PASS - save to sentinel-validation-report.txt
sentinel apply -global "tfplan=$(cat module4-architecture/sentinel/test/secure-tfplan.json)" module4-architecture/sentinel/policies/s3-security.sentinel >> module4-architecture/reports/sentinel-validation-report.txt

# Sentinel Test 5: Encryption policy against secure plan PASS - save to sentinel-validation-report.txt
sentinel apply -global "tfplan=$(cat module4-architecture/sentinel/test/secure-tfplan.json)" module4-architecture/sentinel/policies/encryption.sentinel >> module4-architecture/reports/sentinel-validation-report.txt

# Sentinel Test 6: Network policy against secure plan PASS - save to sentinel-validation-report.txt
sentinel apply -global "tfplan=$(cat module4-architecture/sentinel/test/secure-tfplan.json)" module4-architecture/sentinel/policies/network-security.sentinel >> module4-architecture/reports/sentinel-validation-report.txt

# Ansible syntax check hardening playbook - save to ansible-hardening-report-ec2.txt
ansible-playbook --syntax-check module4-architecture/ansible/hardening-playbook.yml >> module4-architecture/reports/ansible-hardening-report-ec2.txt

# Ansible syntax check reset playbook - save to ansible-hardening-report-ec2.txt
ansible-playbook --syntax-check module4-architecture/ansible/reset-playbook.yml >> module4-architecture/reports/ansible-hardening-report-ec2.txt

# Terraform validate insecure infrastructure - save output
cd module4-architecture/terraform && terraform validate insecure-infra.tf >> ../reports/opa-validation-report.txt && cd ../..

# Terraform validate secure infrastructure - save output
cd module4-architecture/terraform && terraform validate secure-infra.tf >> ../reports/opa-validation-report.txt && cd ../..
