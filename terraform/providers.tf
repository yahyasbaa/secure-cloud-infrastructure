terraform {
  required_version = ">= 1.11.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.67"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.9"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.4"
    }
  }

  # Partial configuration: supply the bucket/region/key with
  #   terraform init -backend-config=environments/<env>/backend.hcl
  # State is encrypted with a customer-managed KMS key and locked with S3
  # native lock files (no DynamoDB table required). See terraform/bootstrap.
  backend "s3" {}
}

provider "aws" {
  region = var.aws_region

  # Only true for the local (moto) validation environment.
  s3_use_path_style = var.s3_use_path_style

  # Refuse to run against any account other than the one the environment
  # was configured for: protects against applying dev config to production.
  allowed_account_ids = var.allowed_account_ids

  default_tags {
    tags = {
      Project     = var.project
      Environment = var.environment
      ManagedBy   = "terraform"
      Repository  = var.github_repository
    }
  }
}
