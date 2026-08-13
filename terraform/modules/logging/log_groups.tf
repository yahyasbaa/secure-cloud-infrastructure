resource "aws_cloudwatch_log_group" "app" {
  name              = "/${var.name}/app"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.logs_kms_key_arn
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/${var.name}/vpc-flow-logs"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.logs_kms_key_arn
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/${var.name}/cloudtrail"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.logs_kms_key_arn
}
