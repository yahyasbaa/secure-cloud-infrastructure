# Real-time (seconds, not minutes) notification for the highest-impact
# defence-evasion actions. Complements the metric-filter alarms, which batch
# over 5 minutes.
resource "aws_cloudwatch_event_rule" "defense_evasion" {
  name        = "${var.name}-defense-evasion"
  description = "Logging or key-destruction actions that indicate an attacker covering tracks"
  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["cloudtrail.amazonaws.com", "kms.amazonaws.com", "guardduty.amazonaws.com", "ec2.amazonaws.com"]
      eventName = [
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail",
        "PutEventSelectors",
        "ScheduleKeyDeletion",
        "DisableKey",
        "DeleteDetector",
        "DisassociateFromMasterAccount",
        "DeleteFlowLogs",
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "defense_evasion" {
  rule      = aws_cloudwatch_event_rule.defense_evasion.name
  target_id = "sns"
  arn       = aws_sns_topic.alarms.arn
}

#----------------------------------------------------------------- GuardDuty
resource "aws_guardduty_detector" "this" {
  #checkov:skip=CKV2_AWS_3:Single-account deployment; organization-wide GuardDuty requires an AWS Organizations delegated administrator.
  count                        = var.enable_guardduty ? 1 : 0
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_cloudwatch_event_rule" "guardduty_high" {
  count       = var.enable_guardduty ? 1 : 0
  name        = "${var.name}-guardduty-high-severity"
  description = "GuardDuty findings with severity >= 7 (high/critical)"
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 7] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_high" {
  count     = var.enable_guardduty ? 1 : 0
  rule      = aws_cloudwatch_event_rule.guardduty_high[0].name
  target_id = "sns"
  arn       = aws_sns_topic.alarms.arn
}
