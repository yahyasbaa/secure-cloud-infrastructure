# Multi-region trail capturing all management events (read and write) from
# every region, including global services (IAM, STS, CloudFront). Log file
# integrity validation produces signed digest files so tampering is
# detectable. Events are also streamed to CloudWatch Logs for the metric
# filters and alarms in the monitoring module.

data "aws_iam_policy_document" "cloudtrail_trust" {
  statement {
    sid     = "CloudTrailAssume"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

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
}

resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name                 = "${var.name}-cloudtrail-to-cwl"
  description          = "Lets CloudTrail stream events into the ${var.name} CloudWatch log group"
  assume_role_policy   = data.aws_iam_policy_document.cloudtrail_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "cloudtrail_cloudwatch" {
  statement {
    sid       = "DeliverTrailEvents"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.cloudtrail.arn}:log-stream:*"]
  }
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name   = "deliver-trail-events"
  role   = aws_iam_role.cloudtrail_cloudwatch.id
  policy = data.aws_iam_policy_document.cloudtrail_cloudwatch.json
}

resource "aws_cloudtrail" "this" {
  #checkov:skip=CKV_AWS_252:Per-file SNS delivery notifications are noise; alerting is done through CloudWatch metric filters and alarms on the trail's log group.
  name                          = var.trail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  enable_logging                = true
  kms_key_id                    = var.logs_kms_key_arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cloudwatch.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}
