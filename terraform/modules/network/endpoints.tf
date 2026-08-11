locals {
  # Explicit per-service allow lists for endpoints that support policies.
  # SSM agent endpoints (ssm, ssmmessages, ec2messages) use the default
  # policy because the agent's API surface is large and version dependent;
  # IAM on the instance role still restricts what can be called.
  endpoint_policy_actions = {
    "secretsmanager" = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"]
    "logs"           = ["logs:CreateLogStream", "logs:DescribeLogStreams", "logs:PutLogEvents"]
    "ecr.api"        = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetAuthorizationToken", "ecr:GetDownloadUrlForLayer"]
    "ecr.dkr"        = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetAuthorizationToken", "ecr:GetDownloadUrlForLayer"]
  }
}

# S3 gateway endpoint (free). Its policy is an egress allow-list: instances
# can only *read* from the buckets they need (OS packages, ECR image layers,
# SSM agent artifacts) and cannot write to any bucket, including an
# attacker-controlled one.
data "aws_iam_policy_document" "s3_endpoint" {
  statement {
    sid     = "ReadOnlyRequiredBuckets"
    effect  = "Allow"
    actions = ["s3:GetObject"]
    resources = [
      "arn:${var.partition}:s3:::al2023-repos-${var.region}-de612dc2/*",
      "arn:${var.partition}:s3:::prod-${var.region}-starport-layer-bucket/*",
      "arn:${var.partition}:s3:::amazon-ssm-${var.region}/*",
      "arn:${var.partition}:s3:::amazon-ssm-packages-${var.region}/*",
      "arn:${var.partition}:s3:::${var.region}-birdwatcher-prod/*",
      "arn:${var.partition}:s3:::aws-ssm-document-attachments-${var.region}/*",
      "arn:${var.partition}:s3:::patch-baseline-snapshot-${var.region}/*",
    ]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.app.id]
  policy            = data.aws_iam_policy_document.s3_endpoint.json

  tags = { Name = "${var.name}-s3-gateway" }
}

data "aws_iam_policy_document" "interface_endpoint" {
  for_each = local.endpoint_policy_actions

  statement {
    sid       = "SameAccountOnly"
    effect    = "Allow"
    actions   = each.value
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_vpc_endpoint" "interface" {
  for_each = toset(var.interface_endpoint_services)

  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = slice(aws_subnet.app[*].id, 0, min(var.interface_endpoint_az_count, local.az_count))
  security_group_ids  = [aws_security_group.endpoints.id]
  policy              = contains(keys(local.endpoint_policy_actions), each.value) ? data.aws_iam_policy_document.interface_endpoint[each.value].json : null

  tags = { Name = "${var.name}-${replace(each.value, ".", "-")}-endpoint" }
}
