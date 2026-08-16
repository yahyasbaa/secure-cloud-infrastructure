# Human operator roles. Both require MFA (and an MFA session younger than one
# hour) to assume, and both are read-only.

data "aws_iam_policy_document" "operator_trust" {
  statement {
    sid     = "OperatorsWithMfa"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = var.operator_principal_arns
    }

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }

    condition {
      test     = "NumericLessThan"
      variable = "aws:MultiFactorAuthAge"
      values   = ["3600"]
    }
  }
}

###############################################################################
# Monitoring: on-call engineers read metrics, alarms and project logs.
###############################################################################
resource "aws_iam_role" "monitoring" {
  name                 = "${var.name}-monitoring"
  description          = "Read-only observability access for on-call engineers"
  assume_role_policy   = data.aws_iam_policy_document.operator_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "monitoring" {
  statement {
    sid    = "ReadMetricsAndAlarms"
    effect = "Allow"
    actions = [
      "cloudwatch:DescribeAlarmsForMetric",
      "cloudwatch:DescribeAnomalyDetectors",
      "cloudwatch:GetMetricData",
      "cloudwatch:GetMetricStatistics",
      "cloudwatch:ListMetrics",
    ]
    resources = ["*"] # these APIs do not support resource-level permissions
  }

  statement {
    sid       = "ReadProjectAlarms"
    effect    = "Allow"
    actions   = ["cloudwatch:DescribeAlarmHistory", "cloudwatch:DescribeAlarms"]
    resources = var.alarm_arns
  }

  statement {
    sid    = "ReadProjectLogs"
    effect = "Allow"
    actions = [
      "logs:DescribeLogStreams",
      "logs:FilterLogEvents",
      "logs:GetLogEvents",
    ]
    resources = concat(
      var.readable_log_group_arns,
      [for arn in var.readable_log_group_arns : "${arn}:log-stream:*"],
    )
  }
}

resource "aws_iam_role_policy" "monitoring" {
  name   = "read-observability"
  role   = aws_iam_role.monitoring.id
  policy = data.aws_iam_policy_document.monitoring.json
}

###############################################################################
# Security audit: inspects configuration and the audit trail. Explicitly
# denied from reading secret values, decrypting data or reading objects, so an
# auditor credential leak cannot become a data breach.
###############################################################################
resource "aws_iam_role" "security_audit" {
  name                 = "${var.name}-security-audit"
  description          = "Read-only configuration and audit-trail access for security reviewers"
  assume_role_policy   = data.aws_iam_policy_document.operator_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "security_audit" {
  statement {
    sid    = "AuditAccountInventory"
    effect = "Allow"
    actions = [
      "cloudtrail:DescribeTrails",
      "cloudtrail:LookupEvents",
      "ec2:DescribeFlowLogs",
      "ec2:DescribeInstances",
      "ec2:DescribeNetworkAcls",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeRouteTables",
      "ec2:DescribeSecurityGroupRules",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeVpcEndpoints",
      "ec2:DescribeVpcs",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeTargetGroups",
      "guardduty:ListDetectors",
      "iam:GenerateCredentialReport",
      "iam:GetAccountAuthorizationDetails",
      "iam:GetAccountPasswordPolicy",
      "iam:GetAccountSummary",
      "iam:GetCredentialReport",
      "iam:ListOpenIDConnectProviders",
      "iam:ListPolicies",
      "iam:ListRoles",
      "kms:ListAliases",
      "kms:ListKeys",
      "s3:ListAllMyBuckets",
      "secretsmanager:ListSecrets",
    ]
    resources = ["*"] # list/describe APIs without resource-level permissions
  }

  statement {
    sid    = "AuditProjectRoles"
    effect = "Allow"
    actions = [
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:ListAttachedRolePolicies",
      "iam:ListRolePolicies",
    ]
    resources = concat(local.own_role_arns, var.service_role_arns)
  }

  statement {
    sid    = "AuditProjectKeys"
    effect = "Allow"
    actions = [
      "kms:DescribeKey",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
    ]
    resources = [var.data_kms_key_arn, var.logs_kms_key_arn]
  }

  statement {
    sid    = "AuditProjectBuckets"
    effect = "Allow"
    actions = [
      "s3:GetBucketLogging",
      "s3:GetBucketOwnershipControls",
      "s3:GetBucketPolicy",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketVersioning",
      "s3:GetEncryptionConfiguration",
      "s3:GetLifecycleConfiguration",
    ]
    resources = var.log_bucket_arns
  }

  statement {
    sid       = "AuditTrailStatus"
    effect    = "Allow"
    actions   = ["cloudtrail:GetEventSelectors", "cloudtrail:GetTrailStatus"]
    resources = [var.cloudtrail_arn]
  }

  statement {
    sid       = "AuditTrailLogs"
    effect    = "Allow"
    actions   = ["logs:FilterLogEvents", "logs:GetLogEvents"]
    resources = [var.cloudtrail_log_group_arn, "${var.cloudtrail_log_group_arn}:log-stream:*"]
  }

  statement {
    sid       = "AuditSecretMetadata"
    effect    = "Allow"
    actions   = ["secretsmanager:DescribeSecret", "secretsmanager:GetResourcePolicy"]
    resources = [var.app_secret_arn, var.db_secret_arn]
  }

  statement {
    sid       = "AuditDatabase"
    effect    = "Allow"
    actions   = ["rds:DescribeDBInstances"]
    resources = [var.db_instance_arn]
  }

  statement {
    sid    = "DenyDataPlaneAccess"
    effect = "Deny"
    actions = [
      "kms:Decrypt",
      "rds-db:connect",
      "s3:GetObject",
      "s3:GetObjectVersion",
      "secretsmanager:GetSecretValue",
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
    ]
    resources = ["*"]
  }
}

locals {
  own_role_arns = [
    aws_iam_role.app.arn,
    aws_iam_role.deployment.arn,
    aws_iam_role.monitoring.arn,
    aws_iam_role.security_audit.arn,
  ]
}

resource "aws_iam_role_policy" "security_audit" {
  name   = "audit-read-only"
  role   = aws_iam_role.security_audit.id
  policy = data.aws_iam_policy_document.security_audit.json
}
