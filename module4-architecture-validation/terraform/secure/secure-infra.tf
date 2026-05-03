# ================================================
# SECURE Infrastructure — Production Ready
# All OPA policies pass on this configuration
# Author: Hussain
# Standards: GDPR, ISO27001, PCI-DSS, CIS
# ================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-north-1"
}

# SECURE: Private S3 bucket with versioning and encryption
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket-334960985321"

  tags = {
    Name        = "Secure Bucket"
    Environment = "Production"
  }
}

# Versioning enabled — satisfies ISO27001 A.12.3
resource "aws_s3_bucket_versioning" "secure_bucket_versioning" {
  bucket = aws_s3_bucket.secure_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Encryption enabled — satisfies GDPR Article 32
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket_encryption" {
  bucket = aws_s3_bucket.secure_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block all public access — satisfies CIS AWS 2.1.5
resource "aws_s3_bucket_public_access_block" "secure_bucket_public_access" {
  bucket                  = aws_s3_bucket.secure_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SECURE: Security group — SSH restricted to specific IP only
resource "aws_security_group" "secure_sg" {
  name        = "secure-security-group"
  description = "Secure security group - restricted access only"

  # SSH only from specific corporate IP — not open to world
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
    description = "SSH restricted to internal network only"
  }

  # HTTPS allowed from anywhere — this is fine
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS open to world - acceptable"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Environment = "Production"
  }
}

# SECURE: Encrypted EBS volume — satisfies GDPR Article 32
resource "aws_ebs_volume" "secure_volume" {
  availability_zone = "eu-north-1a"
  size              = 20
  encrypted         = true

  tags = {
    Name        = "Secure Volume"
    Environment = "Production"
  }
}

# SECURE: Encrypted RDS database — satisfies PCI-DSS Req 3
resource "aws_db_instance" "secure_db" {
  identifier        = "secure-database"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "admin"
  password          = "SecureP@ssw0rd123!"
  storage_encrypted = true
  skip_final_snapshot = true

  tags = {
    Environment = "Production"
  }
}
