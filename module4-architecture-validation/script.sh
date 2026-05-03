#!/bin/bash

# OPA Test 1: S3 Security against insecure infrastructure - save to opa-validation-report.txt
opa eval --data module4-architecture-validation/opa/policies/s3-security.rego --input module4-architecture-validation/opa/test/insecure-input.json --format pretty "data.aws.s3.security.deny" >> module4-architecture-validation/reports/opa-validation-report.txt

# OPA Test 2: Network Security against insecure infrastructure - save to opa-validation-report.txt
opa eval --data module4-architecture-validation/opa/policies/security-group.rego --input module4-architecture-validation/opa/test/insecure-input.json --format pretty "data.aws.security.network.deny" >> module4-architecture-validation/reports/opa-validation-report.txt

# OPA Test 3: Encryption Policy against insecure infrastructure - save to opa-validation-report.txt
opa eval --data module4-architecture-validation/opa/policies/encryption.rego --input module4-architecture-validation/opa/test/insecure-input.json --format pretty "data.aws.encryption.deny" >> module4-architecture-validation/reports/opa-validation-report.txt

# OPA Test 4: All policies against secure infrastructure (empty) - save to opa-validation-report.txt
opa eval --data module4-architecture-validation/opa/policies/ --input module4-architecture-validation/opa/test/secure-input.json --format pretty "data.aws.s3.security.deny" >> module4-architecture-validation/reports/opa-validation-report.txt

# Sentinel Test 1: S3 policy against insecure plan FAIL - save to sentinel-validation-report.txt
sentinel apply -global "tfplan=$(cat module4-architecture-validation/sentinel/test/insecure-tfplan.json)" module4-architecture-validation/sentinel/policies/s3-security.sentinel >> module4-architecture-validation/reports/sentinel-validation-report.txt

# Sentinel Test 2: Encryption policy against insecure plan FAIL - save to sentinel-validation-report.txt
sentinel apply -global "tfplan=$(cat module4-architecture-validation/sentinel/test/insecure-tfplan.json)" module4-architecture-validation/sentinel/policies/encryption.sentinel >> module4-architecture-validation/reports/sentinel-validation-report.txt

# Sentinel Test 3: Network policy against insecure plan FAIL - save to sentinel-validation-report.txt
sentinel apply -global "tfplan=$(cat module4-architecture-validation/sentinel/test/insecure-tfplan.json)" module4-architecture-validation/sentinel/policies/network-security.sentinel >> module4-architecture-validation/reports/sentinel-validation-report.txt

# Sentinel Test 4: S3 policy against secure plan PASS - save to sentinel-validation-report.txt
sentinel apply -global "tfplan=$(cat module4-architecture-validation/sentinel/test/secure-tfplan.json)" module4-architecture-validation/sentinel/policies/s3-security.sentinel >> module4-architecture-validation/reports/sentinel-validation-report.txt

# Sentinel Test 5: Encryption policy against secure plan PASS - save to sentinel-validation-report.txt
sentinel apply -global "tfplan=$(cat module4-architecture-validation/sentinel/test/secure-tfplan.json)" module4-architecture-validation/sentinel/policies/encryption.sentinel >> module4-architecture-validation/reports/sentinel-validation-report.txt

# Sentinel Test 6: Network policy against secure plan PASS - save to sentinel-validation-report.txt
sentinel apply -global "tfplan=$(cat module4-architecture-validation/sentinel/test/secure-tfplan.json)" module4-architecture-validation/sentinel/policies/network-security.sentinel >> module4-architecture-validation/reports/sentinel-validation-report.txt

# Terraform validate insecure infrastructure - save output
cd module4-architecture-validation/terraform/insecure && terraform init >> ../../reports/opa-validation-report.txt 2>&1 && terraform validate >> ../../reports/opa-validation-report.txt 2>&1 && cd ../..

# Terraform validate secure infrastructure - save output
cd module4-architecture-validation/terraform/secure && terraform init >> ../../reports/opa-validation-report.txt 2>&1 && terraform validate >> ../../reports/opa-validation-report.txt 2>&1 && cd ../..
