# One-time bootstrap of the remote state backend (run once per account with
# administrator credentials; see README "Deploy to AWS").
#
# Creates:
#   * a customer-managed KMS key for Terraform state
#   * a versioned, KMS-encrypted, TLS-only, non-public S3 bucket for state,
#     using S3 native lock files (no DynamoDB table)
#   * an access-log bucket recording every read/write of the state
#
# This stack keeps its own (tiny, secret-free) state locally in
# terraform/bootstrap/terraform.tfstate, which is git-ignored.

terraform {
  required_version = ">= 1.11.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.67"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = var.project
      ManagedBy = "terraform"
      Stack     = "bootstrap"
    }
  }
}

variable "project" {
  description = "Project prefix."
  type        = string
  default     = "sci"
}

variable "aws_region" {
  description = "Region for the state bucket."
  type        = string
  default     = "us-east-1"
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  root_arn   = "arn:${data.aws_partition.current.partition}:iam::${local.account_id}:root"
  bucket     = "${var.project}-tfstate-${local.account_id}-${var.aws_region}"
}

data "aws_iam_policy_document" "state_key" {
  #checkov:skip=CKV_AWS_111:Key policy, not an identity policy: Resource "*" means "this key" and is mandatory in KMS key policies.
  #checkov:skip=CKV_AWS_356:Key policy, not an identity policy: Resource "*" means "this key" and is mandatory in KMS key policies.
  #checkov:skip=CKV_AWS_109:Key policy, not an identity policy: kms:PutKeyPolicy/CreateGrant are scoped to this key and delegated to IAM in the account.
  statement {
    sid    = "AccountKeyAdministrationAndUse"
    effect = "Allow"
    actions = [
      "kms:CancelKeyDeletion",
      "kms:CreateAlias",
      "kms:CreateGrant",
      "kms:Decrypt",
      "kms:DeleteAlias",
      "kms:DescribeKey",
      "kms:DisableKey",
      "kms:EnableKey",
      "kms:EnableKeyRotation",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:ListAliases",
      "kms:ListKeyRotations",
      "kms:ListResourceTags",
      "kms:PutKeyPolicy",
      "kms:ReEncryptFrom",
      "kms:ReEncryptTo",
      "kms:ScheduleKeyDeletion",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:UpdateAlias",
      "kms:UpdateKeyDescription",
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.root_arn]
    }
  }
}

resource "aws_kms_key" "state" {
  description             = "${var.project} Terraform state encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.state_key.json
}

resource "aws_kms_alias" "state" {
  name          = "alias/${var.project}-tfstate"
  target_key_id = aws_kms_key.state.key_id
}

#--------------------------------------------------------- access log bucket
#tfsec:ignore:aws-s3-enable-bucket-logging -- this IS the access-log target bucket
resource "aws_s3_bucket" "state_logs" {
  #checkov:skip=CKV_AWS_18:This is the access-log target bucket; logging it to itself would recurse.
  #checkov:skip=CKV_AWS_145:S3 server access logging only supports SSE-S3 target buckets.
  #checkov:skip=CKV_AWS_144:Single-region dev environment; cross-region replication is a documented production enhancement.
  #checkov:skip=CKV2_AWS_62:Event notifications are not needed for log storage; security events are alarmed from CloudTrail.
  bucket = "${local.bucket}-access-logs"
}

resource "aws_s3_bucket_ownership_controls" "state_logs" {
  bucket = aws_s3_bucket.state_logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "state_logs" {
  bucket                  = aws_s3_bucket.state_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "state_logs" {
  bucket = aws_s3_bucket.state_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

#tfsec:ignore:aws-s3-encryption-customer-key -- log delivery (S3 access logs / ELB) only supports SSE-S3 targets
resource "aws_s3_bucket_server_side_encryption_configuration" "state_logs" {
  bucket = aws_s3_bucket.state_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "state_logs" {
  bucket = aws_s3_bucket.state_logs.id
  rule {
    id     = "expire-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = 365
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "state_logs" {
  statement {
    sid       = "S3ServerAccessLogDelivery"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.state_logs.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.state_logs.arn, "${aws_s3_bucket.state_logs.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "state_logs" {
  bucket     = aws_s3_bucket.state_logs.id
  policy     = data.aws_iam_policy_document.state_logs.json
  depends_on = [aws_s3_bucket_public_access_block.state_logs]
}

#---------------------------------------------------------------- state bucket
resource "aws_s3_bucket" "state" {
  #checkov:skip=CKV_AWS_144:Single-region dev environment; cross-region replication is a documented production enhancement.
  #checkov:skip=CKV2_AWS_62:Event notifications are not needed for log storage; security events are alarmed from CloudTrail.
  bucket = local.bucket

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.state.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "state" {
  bucket        = aws_s3_bucket.state.id
  target_bucket = aws_s3_bucket.state_logs.id
  target_prefix = "state/"
  depends_on    = [aws_s3_bucket_policy.state_logs]
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    id     = "retain-history"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "state" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # State may only be written encrypted with the state key.
  statement {
    sid       = "DenyWrongEncryptionKey"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.state.arn}/*.tfstate"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.state.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "state" {
  bucket     = aws_s3_bucket.state.id
  policy     = data.aws_iam_policy_document.state.json
  depends_on = [aws_s3_bucket_public_access_block.state]
}

output "backend_config" {
  description = "Paste into terraform/environments/<env>/backend.hcl"
  value       = <<-EOT
    bucket       = "${aws_s3_bucket.state.id}"
    key          = "dev/terraform.tfstate"
    region       = "${var.aws_region}"
    encrypt      = true
    kms_key_id   = "${aws_kms_key.state.arn}"
    use_lockfile = true
  EOT
}

output "state_bucket" {
  description = "Terraform state bucket name."
  value       = aws_s3_bucket.state.id
}

output "state_logs_bucket" {
  description = "Access-log bucket for the state bucket."
  value       = aws_s3_bucket.state_logs.id
}

output "state_kms_key_arn" {
  description = "KMS key encrypting Terraform state."
  value       = aws_kms_key.state.arn
}
