# Two customer-managed keys separate duties:
#   data - RDS storage, RDS-managed master secret, application secret, EBS
#          volumes, ECR images, Performance Insights
#   logs - CloudTrail, CloudWatch Logs, SNS alarm topic
# A compromise of an application credential that can decrypt data therefore
# cannot read or tamper with the audit trail, and vice versa.
#
# Neither key policy uses "kms:*". The account root receives an explicit list
# of administration + usage actions, which delegates access control to IAM
# policies; each IAM policy then grants only what its role needs.

locals {
  root_arn = "arn:${var.partition}:iam::${var.account_id}:root"

  kms_admin_actions = [
    "kms:CancelKeyDeletion",
    "kms:CreateAlias",
    "kms:CreateGrant",
    "kms:DeleteAlias",
    "kms:DescribeKey",
    "kms:DisableKey",
    "kms:DisableKeyRotation",
    "kms:EnableKey",
    "kms:EnableKeyRotation",
    "kms:GetKeyPolicy",
    "kms:GetKeyRotationStatus",
    "kms:ListAliases",
    "kms:ListGrants",
    "kms:ListKeyPolicies",
    "kms:ListKeyRotations",
    "kms:ListResourceTags",
    "kms:PutKeyPolicy",
    "kms:RetireGrant",
    "kms:RevokeGrant",
    "kms:RotateKeyOnDemand",
    "kms:ScheduleKeyDeletion",
    "kms:TagResource",
    "kms:UntagResource",
    "kms:UpdateAlias",
    "kms:UpdateKeyDescription",
  ]

  kms_usage_actions = [
    "kms:Decrypt",
    "kms:DescribeKey",
    "kms:Encrypt",
    "kms:GenerateDataKey",
    "kms:GenerateDataKeyWithoutPlaintext",
    "kms:ReEncryptFrom",
    "kms:ReEncryptTo",
  ]

  log_group_arn_patterns = [
    for p in var.log_group_prefixes : "arn:${var.partition}:logs:${var.region}:${var.account_id}:log-group:${p}*"
  ]
}

# Auto Scaling launches instances with encrypted EBS volumes on our behalf, so
# its service-linked role must be allowed to use the data key. A dedicated,
# suffixed SLR avoids clashing with the account's default SLR.
resource "aws_iam_service_linked_role" "autoscaling" {
  aws_service_name = "autoscaling.amazonaws.com"
  custom_suffix    = var.name
  description      = "Auto Scaling SLR for ${var.name}; trusted by the ${var.name} data KMS key for EBS encryption."
}

data "aws_iam_policy_document" "data_key" {
  #checkov:skip=CKV_AWS_111:Key policy, not an identity policy: Resource "*" means "this key" and is mandatory in KMS key policies.
  #checkov:skip=CKV_AWS_356:Key policy, not an identity policy: Resource "*" means "this key" and is mandatory in KMS key policies.
  statement {
    sid       = "AccountKeyAdministration"
    effect    = "Allow"
    actions   = local.kms_admin_actions
    resources = ["*"] # In a key policy "*" means "this key".

    principals {
      type        = "AWS"
      identifiers = [local.root_arn]
    }
  }

  statement {
    sid       = "AccountKeyUsageViaIam"
    effect    = "Allow"
    actions   = local.kms_usage_actions
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.root_arn]
    }
  }

  statement {
    sid       = "AutoScalingEbsEncryption"
    effect    = "Allow"
    actions   = local.kms_usage_actions
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_service_linked_role.autoscaling.arn]
    }

    # Only usable for EBS operations performed by EC2 on the SLR's behalf.
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ec2.${var.region}.amazonaws.com"]
    }
  }

  statement {
    sid       = "AutoScalingEbsGrants"
    effect    = "Allow"
    actions   = ["kms:CreateGrant"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_service_linked_role.autoscaling.arn]
    }

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }
}

resource "aws_kms_key" "data" {
  description             = "${var.name} data encryption (RDS, secrets, EBS, ECR)"
  key_usage               = "ENCRYPT_DECRYPT"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = var.key_deletion_window_days
  policy                  = data.aws_iam_policy_document.data_key.json
}

resource "aws_kms_alias" "data" {
  name          = "alias/${var.name}-data"
  target_key_id = aws_kms_key.data.key_id
}

data "aws_iam_policy_document" "logs_key" {
  #checkov:skip=CKV_AWS_111:Key policy, not an identity policy: Resource "*" means "this key" and is mandatory in KMS key policies.
  #checkov:skip=CKV_AWS_356:Key policy, not an identity policy: Resource "*" means "this key" and is mandatory in KMS key policies.
  statement {
    sid       = "AccountKeyAdministration"
    effect    = "Allow"
    actions   = local.kms_admin_actions
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.root_arn]
    }
  }

  statement {
    sid       = "AccountKeyUsageViaIam"
    effect    = "Allow"
    actions   = local.kms_usage_actions
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.root_arn]
    }
  }

  statement {
    sid    = "CloudWatchLogsEncryption"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:ReEncryptFrom",
      "kms:ReEncryptTo",
    ]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = local.log_group_arn_patterns
    }
  }

  statement {
    sid       = "CloudTrailEncryptLogs"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${var.partition}:cloudtrail:${var.region}:${var.account_id}:trail/${var.trail_name}"]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:${var.partition}:cloudtrail:*:${var.account_id}:trail/*"]
    }
  }

  statement {
    sid       = "CloudTrailDescribeKey"
    effect    = "Allow"
    actions   = ["kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${var.partition}:cloudtrail:${var.region}:${var.account_id}:trail/${var.trail_name}"]
    }
  }

  # CloudWatch alarms and EventBridge publish to the KMS-encrypted SNS topic.
  statement {
    sid       = "AlarmPublishersUseKey"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com", "events.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_kms_key" "logs" {
  description             = "${var.name} log encryption (CloudTrail, CloudWatch Logs, SNS)"
  key_usage               = "ENCRYPT_DECRYPT"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = var.key_deletion_window_days
  policy                  = data.aws_iam_policy_document.logs_key.json
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${var.name}-logs"
  target_key_id = aws_kms_key.logs.key_id
}
