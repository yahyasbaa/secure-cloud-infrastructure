output "app_log_group_name" {
  description = "Application log group name."
  value       = aws_cloudwatch_log_group.app.name
}

output "app_log_group_arn" {
  description = "Application log group ARN."
  value       = aws_cloudwatch_log_group.app.arn
}

output "cloudtrail_log_group_name" {
  description = "CloudTrail log group name."
  value       = aws_cloudwatch_log_group.cloudtrail.name
}

output "cloudtrail_log_group_arn" {
  description = "CloudTrail log group ARN."
  value       = aws_cloudwatch_log_group.cloudtrail.arn
}

output "log_group_arns" {
  description = "ARNs of all log groups owned by this module."
  value = [
    aws_cloudwatch_log_group.app.arn,
    aws_cloudwatch_log_group.flow_logs.arn,
    aws_cloudwatch_log_group.cloudtrail.arn,
  ]
}

output "cloudtrail_arn" {
  description = "CloudTrail trail ARN."
  value       = aws_cloudtrail.this.arn
}

output "cloudtrail_role_arn" {
  description = "Role CloudTrail uses to deliver to CloudWatch Logs."
  value       = aws_iam_role.cloudtrail_cloudwatch.arn
}

output "flow_logs_log_group_arn" {
  description = "VPC flow log group ARN."
  value       = aws_cloudwatch_log_group.flow_logs.arn
}

output "cloudtrail_bucket" {
  description = "CloudTrail bucket name."
  value       = aws_s3_bucket.cloudtrail.id
}

output "alb_logs_bucket" {
  description = "ALB log bucket name."
  value       = aws_s3_bucket.alb_logs.id
}

output "access_logs_bucket" {
  description = "S3 server access log bucket name."
  value       = aws_s3_bucket.access_logs.id
}

output "bucket_arns" {
  description = "ARNs of all log buckets."
  value       = [aws_s3_bucket.access_logs.arn, aws_s3_bucket.cloudtrail.arn, aws_s3_bucket.alb_logs.arn]
}
