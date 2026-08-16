# Deployment role assumed by GitHub Actions through OIDC: no long-lived AWS
# keys exist anywhere. The trust policy pins the exact repository AND the
# GitHub environment, so a workflow on a fork, an unprotected branch, or a
# pull request cannot assume it. Environment protection rules (required
# reviewers, branch restrictions) are enforced by GitHub before the token is
# issued.
#
# Scope: ship a new application image. It can push to one ECR repository,
# update one SSM parameter and roll one Auto Scaling group. It cannot change
# infrastructure, IAM, networking or data stores; infrastructure changes are
# applied by an administrator with `terraform apply` (see README).

locals {
  github_oidc_url  = "https://token.actions.githubusercontent.com"
  github_oidc_host = "token.actions.githubusercontent.com"
}

resource "aws_iam_openid_connect_provider" "github" {
  count          = var.create_github_oidc_provider ? 1 : 0
  url            = local.github_oidc_url
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_openid_connect_provider" "github" {
  count = var.create_github_oidc_provider ? 0 : 1
  url   = local.github_oidc_url
}

locals {
  github_oidc_provider_arn = var.create_github_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.github[0].arn
}

data "aws_iam_policy_document" "deployment_trust" {
  statement {
    sid     = "GitHubActionsOidc"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.github_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.github_oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.github_oidc_host}:sub"
      values   = ["repo:${var.github_repository}:environment:${var.github_environment}"]
    }
  }
}

resource "aws_iam_role" "deployment" {
  name                 = "${var.name}-deployment"
  description          = "Assumed by GitHub Actions (OIDC) to ship application images"
  assume_role_policy   = data.aws_iam_policy_document.deployment_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "deployment" {
  statement {
    sid       = "EcrAuthToken"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"] # API does not support resource-level permissions
  }

  statement {
    sid    = "PushAppImage"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:CompleteLayerUpload",
      "ecr:DescribeImageScanFindings",
      "ecr:DescribeImages",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
    ]
    resources = [local.ecr_repository_arn]
  }

  statement {
    sid       = "PublishImageTag"
    effect    = "Allow"
    actions   = ["ssm:GetParameter", "ssm:PutParameter"]
    resources = [local.image_tag_parameter_arn]
  }

  statement {
    sid       = "RollOutInstances"
    effect    = "Allow"
    actions   = ["autoscaling:CancelInstanceRefresh", "autoscaling:StartInstanceRefresh"]
    resources = [var.asg_arn]
  }

  statement {
    sid    = "ObserveRollout"
    effect = "Allow"
    actions = [
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeInstanceRefreshes",
    ]
    resources = ["*"] # Describe APIs do not support resource-level permissions
  }
}

resource "aws_iam_role_policy" "deployment" {
  name   = "ship-application"
  role   = aws_iam_role.deployment.id
  policy = data.aws_iam_policy_document.deployment.json
}
