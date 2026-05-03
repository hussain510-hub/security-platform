# ================================================
# INSECURE Infrastructure — FOR OPA TESTING ONLY
# This file contains intentional violations to
# demonstrate OPA blocking bad deployments
# Author: Hussain
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

# VIOLATION 1: Public S3 bucket — OPA will block this
resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "my-insecure-bucket-334960985321"
  acl    = "public-read"

  tags = {
    Name        = "Insecure Bucket"
    Environment = "Test"
  }
}

# VIOLATION 2: S3 bucket with no versioning — OPA will block this
resource "aws_s3_bucket" "no_versioning_bucket" {
  bucket = "my-no-versioning-bucket-334960985321"

  tags = {
    Name        = "No Versioning Bucket"
    Environment = "Test"
  }
}

# VIOLATION 3: Security group open SSH — OPA will block this
resource "aws_security_group" "insecure_sg" {
  name        = "insecure-security-group"
  description = "Insecure security group for OPA testing"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH open to world - VIOLATION"
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "RDP open to world - VIOLATION"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Environment = "Test"
  }
}

# VIOLATION 4: Unencrypted EBS volume — OPA will block this
resource "aws_ebs_volume" "insecure_volume" {
  availability_zone = "eu-north-1a"
  size              = 20
  encrypted         = false

  tags = {
    Name        = "Insecure Volume"
    Environment = "Test"
  }
}

# VIOLATION 5: Unencrypted RDS database — OPA will block this
resource "aws_db_instance" "insecure_db" {
  identifier        = "insecure-database"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "admin"
  password          = "password123"
  storage_encrypted = false
  skip_final_snapshot = true

  tags = {
    Environment = "Test"
  }
}
