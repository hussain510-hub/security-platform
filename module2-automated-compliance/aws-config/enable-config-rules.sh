#!/bin/bash
# ================================================
# AWS Config Compliance Rules Setup Script
# Author: Hussain
# Description: Enables AWS Config and compliance rules
# ================================================

ACCOUNT_ID="334960985321"
REGION="eu-north-1"
BUCKET_NAME="security-platform-config-${ACCOUNT_ID}"

echo "Step 1: Creating S3 bucket for AWS Config..."
aws s3 mb s3://${BUCKET_NAME} --region ${REGION}

echo "Step 2: Applying bucket policy..."
aws s3api put-bucket-policy \
  --bucket ${BUCKET_NAME} \
  --policy "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [
      {
        \"Sid\": \"AWSConfigBucketPermissionsCheck\",
        \"Effect\": \"Allow\",
        \"Principal\": {\"Service\": \"config.amazonaws.com\"},
        \"Action\": \"s3:GetBucketAcl\",
        \"Resource\": \"arn:aws:s3:::${BUCKET_NAME}\"
      },
      {
        \"Sid\": \"AWSConfigBucketDelivery\",
        \"Effect\": \"Allow\",
        \"Principal\": {\"Service\": \"config.amazonaws.com\"},
        \"Action\": \"s3:PutObject\",
        \"Resource\": \"arn:aws:s3:::${BUCKET_NAME}/AWSLogs/${ACCOUNT_ID}/Config/*\"
      }
    ]
  }"

echo "Step 3: Creating IAM role for AWS Config..."
aws iam create-role \
  --role-name AWSConfigRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {"Service": "config.amazonaws.com"},
        "Action": "sts:AssumeRole"
      }
    ]
  }'

echo "Step 4: Attaching policies to role..."
aws iam attach-role-policy \
  --role-name AWSConfigRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWS_ConfigRole

aws iam attach-role-policy \
  --role-name AWSConfigRole \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess

echo "Step 5: Enabling Config recorder..."
aws configservice put-configuration-recorder \
  --configuration-recorder name=default,roleARN=arn:aws:iam::${ACCOUNT_ID}:role/AWSConfigRole \
  --recording-group allSupported=true,includeGlobalResourceTypes=true \
  --region ${REGION}

echo "Step 6: Setting delivery channel..."
aws configservice put-delivery-channel \
  --delivery-channel name=default,s3BucketName=${BUCKET_NAME} \
  --region ${REGION}

echo "Step 7: Starting recorder..."
aws configservice start-configuration-recorder \
  --configuration-recorder-name default \
  --region ${REGION}

echo "Step 8: Adding compliance rules..."
aws configservice put-config-rule \
  --config-rule '{"ConfigRuleName":"cloudtrail-enabled","Source":{"Owner":"AWS","SourceIdentifier":"CLOUD_TRAIL_ENABLED"}}' \
  --region ${REGION}

aws configservice put-config-rule \
  --config-rule '{"ConfigRuleName":"encrypted-volumes","Source":{"Owner":"AWS","SourceIdentifier":"ENCRYPTED_VOLUMES"}}' \
  --region ${REGION}

aws configservice put-config-rule \
  --config-rule '{"ConfigRuleName":"iam-password-policy","Source":{"Owner":"AWS","SourceIdentifier":"IAM_PASSWORD_POLICY"}}' \
  --region ${REGION}

echo "Done! AWS Config is now monitoring your account."
aws configservice describe-configuration-recorder-status --region ${REGION}

echo "Step 9: Checking compliance status..."
aws configservice describe-compliance-by-config-rule \
  --region ${REGION}
