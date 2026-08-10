output "data_kms_key_arn" {
  description = "ARN of the data encryption key."
  value       = aws_kms_key.data.arn
}

output "logs_kms_key_arn" {
  description = "ARN of the log encryption key."
  value       = aws_kms_key.logs.arn
}

output "app_secret_arn" {
  description = "ARN of the application API token secret."
  value       = aws_secretsmanager_secret.app_token.arn
}

output "autoscaling_service_linked_role_arn" {
  description = "ARN of the dedicated Auto Scaling service-linked role."
  value       = aws_iam_service_linked_role.autoscaling.arn
}
