# VPC Flow Logs capture ACCEPT and REJECT records for every ENI in the VPC
# (1-minute aggregation) into a KMS-encrypted log group. Rejected-traffic
# records are the evidence trail for blocked lateral movement / scanning.

data "aws_iam_policy_document" "flow_logs_trust" {
  statement {
    sid     = "VpcFlowLogsAssume"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${var.partition}:ec2:${var.region}:${var.account_id}:vpc-flow-log/*"]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  name                 = "${var.name}-vpc-flow-logs"
  description          = "Lets VPC Flow Logs deliver to the ${var.name} flow log group"
  assume_role_policy   = data.aws_iam_policy_document.flow_logs_trust.json
  max_session_duration = 3600
}

#tfsec:ignore:aws-iam-no-policy-wildcards -- log stream names are generated per ENI by the service; scoped to one log group
data "aws_iam_policy_document" "flow_logs" {
  statement {
    sid    = "DeliverFlowLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents",
    ]
    resources = [
      var.flow_log_group_arn,
      "${var.flow_log_group_arn}:log-stream:*",
    ]
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  name   = "deliver-flow-logs"
  role   = aws_iam_role.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs.json
}

resource "aws_flow_log" "vpc" {
  vpc_id                   = aws_vpc.this.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = var.flow_log_group_arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 60

  tags = { Name = "${var.name}-vpc-flow-log" }
}
