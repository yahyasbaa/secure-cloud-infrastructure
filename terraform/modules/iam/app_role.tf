# Application instance role.
#
# Grants exactly what the container host needs at runtime:
#   - read the two secrets it uses (API token, DB credentials)
#   - decrypt them, but only when the call comes through Secrets Manager
#   - write its own log streams
#   - read the deployed image tag and pull that one ECR repository
#   - register with SSM Session Manager (replaces SSH; no key pairs, no port 22)

data "aws_iam_policy_document" "app_trust" {
  statement {
    sid     = "Ec2Assume"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "app" {
  name                 = "${var.name}-app"
  description          = "Runtime identity of the ${var.name} application hosts"
  assume_role_policy   = data.aws_iam_policy_document.app_trust.json
  max_session_duration = 3600
}

resource "aws_iam_instance_profile" "app" {
  name = "${var.name}-app"
  role = aws_iam_role.app.name
}

data "aws_iam_policy_document" "app" {
  statement {
    sid       = "ReadAppSecrets"
    effect    = "Allow"
    actions   = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"]
    resources = [var.app_secret_arn, var.db_secret_arn]
  }

  statement {
    sid       = "DecryptSecretsViaSecretsManager"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [var.data_kms_key_arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.region}.amazonaws.com"]
    }
  }

  statement {
    sid       = "WriteAppLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [var.app_log_group_arn, "${var.app_log_group_arn}:log-stream:*"]
  }

  statement {
    sid       = "ReadImageTag"
    effect    = "Allow"
    actions   = ["ssm:GetParameter"]
    resources = [local.image_tag_parameter_arn]
  }

  statement {
    sid    = "PullAppImage"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
    resources = [local.ecr_repository_arn]
  }

  statement {
    sid       = "EcrAuthToken"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"] # API does not support resource-level permissions
  }

  statement {
    sid       = "SsmRegisterInstance"
    effect    = "Allow"
    actions   = ["ssm:UpdateInstanceInformation"]
    resources = ["arn:${var.partition}:ec2:${var.region}:${var.account_id}:instance/*"]
  }

  statement {
    sid    = "SsmSessionChannels"
    effect = "Allow"
    actions = [
      "ec2messages:AcknowledgeMessage",
      "ec2messages:DeleteMessage",
      "ec2messages:FailMessage",
      "ec2messages:GetEndpoint",
      "ec2messages:GetMessages",
      "ec2messages:SendReply",
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
    ]
    resources = ["*"] # APIs do not support resource-level permissions
  }
}

resource "aws_iam_role_policy" "app" {
  name   = "app-runtime"
  role   = aws_iam_role.app.id
  policy = data.aws_iam_policy_document.app.json
}
