output "alarm_topic_arn" {
  description = "SNS topic receiving all security alarms."
  value       = aws_sns_topic.alarms.arn
}

output "alarm_names" {
  description = "Names of all CloudWatch alarms created."
  value = concat(
    [for a in aws_cloudwatch_metric_alarm.security : a.alarm_name],
    [
      aws_cloudwatch_metric_alarm.alb_request_anomaly.alarm_name,
      aws_cloudwatch_metric_alarm.unauthorized_api_anomaly.alarm_name,
      aws_cloudwatch_metric_alarm.alb_5xx.alarm_name,
      aws_cloudwatch_metric_alarm.unhealthy_hosts.alarm_name,
      aws_cloudwatch_metric_alarm.db_cpu.alarm_name,
      aws_cloudwatch_metric_alarm.db_storage.alarm_name,
    ],
    [for a in aws_cloudwatch_metric_alarm.waf_blocked_spike : a.alarm_name],
  )
}

output "alarm_arns" {
  description = "ARNs of all CloudWatch alarms created."
  value = concat(
    [for a in aws_cloudwatch_metric_alarm.security : a.arn],
    [
      aws_cloudwatch_metric_alarm.alb_request_anomaly.arn,
      aws_cloudwatch_metric_alarm.unauthorized_api_anomaly.arn,
      aws_cloudwatch_metric_alarm.alb_5xx.arn,
      aws_cloudwatch_metric_alarm.unhealthy_hosts.arn,
      aws_cloudwatch_metric_alarm.db_cpu.arn,
      aws_cloudwatch_metric_alarm.db_storage.arn,
    ],
    [for a in aws_cloudwatch_metric_alarm.waf_blocked_spike : a.arn],
  )
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID (null when disabled)."
  value       = var.enable_guardduty ? aws_guardduty_detector.this[0].id : null
}
