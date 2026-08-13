# Log buckets. Every bucket: versioned, public access fully blocked, ACLs
# disabled (BucketOwnerEnforced), TLS-only bucket policy, lifecycle expiry.
#
# Encryption: the CloudTrail bucket uses the customer-managed logs key.
# The S3 access-log and ALB-log buckets must use SSE-S3 (AES-256) because
# neither S3 server access logging nor ELB log delivery supports SSE-KMS
# destination buckets. See security/suppressions.md.

locals {
  bucket_suffix = "${var.account_id}-${var.region}"
}

data "aws_elb_service_account" "this" {}

###############################################################################
# S3 server access log bucket (target for the other buckets' access logs)
###############################################################################
#tfsec:ignore:aws-s3-enable-bucket-logging -- this IS the access-log target bucket
resource "aws_s3_bucket" "access_logs" {
  #checkov:skip=CKV_AWS_18:This is the access-log target bucket; logging it to itself would recurse.
  #checkov:skip=CKV_AWS_145:S3 server access logging only supports SSE-S3 target buckets.
  #checkov:skip=CKV_AWS_144:Single-region dev environment; cross-region replication is a documented production enhancement.
  #checkov:skip=CKV2_AWS_62:Event notifications are not needed for log storage; security events are alarmed from CloudTrail.
  bucket        = "${var.name}-s3-access-logs-${local.bucket_suffix}"
  force_destroy = var.force_destroy_buckets
}

resource "aws_s3_bucket_ownership_controls" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

#tfsec:ignore:aws-s3-encryption-customer-key -- log delivery (S3 access logs / ELB) only supports SSE-S3 targets
resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    id     = "expire-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = var.log_bucket_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "access_logs" {
  statement {
    sid       = "S3ServerAccessLogDelivery"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.access_logs.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.access_logs.arn, "${aws_s3_bucket.access_logs.arn}/*"]

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

resource "aws_s3_bucket_policy" "access_logs" {
  bucket     = aws_s3_bucket.access_logs.id
  policy     = data.aws_iam_policy_document.access_logs.json
  depends_on = [aws_s3_bucket_public_access_block.access_logs]
}

###############################################################################
# CloudTrail bucket (KMS encrypted with the logs key)
###############################################################################
resource "aws_s3_bucket" "cloudtrail" {
  #checkov:skip=CKV_AWS_144:Single-region dev environment; cross-region replication is a documented production enhancement.
  #checkov:skip=CKV2_AWS_62:Event notifications are not needed for log storage; security events are alarmed from CloudTrail.
  bucket        = "${var.name}-cloudtrail-${local.bucket_suffix}"
  force_destroy = var.force_destroy_buckets
}

resource "aws_s3_bucket_ownership_controls" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.logs_kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "cloudtrail" {
  bucket        = aws_s3_bucket.cloudtrail.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "cloudtrail/"

  # S3 validates that the target bucket policy already authorises log delivery.
  depends_on = [aws_s3_bucket_policy.access_logs]
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    id     = "expire-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = var.log_bucket_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

locals {
  trail_arn = "arn:${var.partition}:cloudtrail:${var.region}:${var.account_id}:trail/${var.trail_name}"
}

data "aws_iam_policy_document" "cloudtrail_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.cloudtrail.arn, "${aws_s3_bucket.cloudtrail.arn}/*"]

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

  # Nobody may delete audit log objects; only the lifecycle rule expires them
  # (lifecycle actions are not subject to bucket policies). This protects the
  # audit trail from an attacker covering their tracks. The statement is
  # removed only when force_destroy_buckets is explicitly enabled for
  # teardown, which is itself a bucket-policy change that raises an alarm.
  dynamic "statement" {
    for_each = var.force_destroy_buckets ? [] : [1]
    content {
      sid       = "DenyLogDeletion"
      effect    = "Deny"
      actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
      resources = ["${aws_s3_bucket.cloudtrail.arn}/*"]

      principals {
        type        = "*"
        identifiers = ["*"]
      }
    }
  }

  statement {
    sid       = "CloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "CloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${var.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket     = aws_s3_bucket.cloudtrail.id
  policy     = data.aws_iam_policy_document.cloudtrail_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.cloudtrail]
}

###############################################################################
# ALB access/connection log bucket (SSE-S3 required by Elastic Load Balancing)
###############################################################################
resource "aws_s3_bucket" "alb_logs" {
  #checkov:skip=CKV_AWS_145:Elastic Load Balancing log delivery only supports SSE-S3 encrypted buckets.
  #checkov:skip=CKV_AWS_144:Single-region dev environment; cross-region replication is a documented production enhancement.
  #checkov:skip=CKV2_AWS_62:Event notifications are not needed for log storage; security events are alarmed from CloudTrail.
  bucket        = "${var.name}-alb-logs-${local.bucket_suffix}"
  force_destroy = var.force_destroy_buckets
}

resource "aws_s3_bucket_ownership_controls" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket                  = aws_s3_bucket.alb_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

#tfsec:ignore:aws-s3-encryption-customer-key -- log delivery (S3 access logs / ELB) only supports SSE-S3 targets
resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_logging" "alb_logs" {
  bucket        = aws_s3_bucket.alb_logs.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "alb-logs/"

  # S3 validates that the target bucket policy already authorises log delivery.
  depends_on = [aws_s3_bucket_policy.access_logs]
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    id     = "expire-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = var.log_bucket_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "alb_logs" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.alb_logs.arn, "${aws_s3_bucket.alb_logs.arn}/*"]

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

  # Regions launched before Aug 2022 deliver as the regional ELB account;
  # newer regions use the log-delivery service principal. Both are scoped to
  # this account's prefix only.
  statement {
    sid       = "ElbLogDeliveryLegacy"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.alb_logs.arn}/AWSLogs/${var.account_id}/*"]

    principals {
      type        = "AWS"
      identifiers = [data.aws_elb_service_account.this.arn]
    }
  }

  statement {
    sid       = "ElbLogDelivery"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.alb_logs.arn}/AWSLogs/${var.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }
  }
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket     = aws_s3_bucket.alb_logs.id
  policy     = data.aws_iam_policy_document.alb_logs.json
  depends_on = [aws_s3_bucket_public_access_block.alb_logs]
}
