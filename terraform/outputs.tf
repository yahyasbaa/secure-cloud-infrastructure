output "alb_dns_name" {
  description = "HTTPS endpoint of the application (https://<this>/health)."
  value       = module.compute.alb_dns_name
}

output "ecr_repository_url" {
  description = "Push application images here."
  value       = module.compute.ecr_repository_url
}

output "asg_name" {
  description = "Auto Scaling group running the application."
  value       = module.compute.asg_name
}

output "image_tag_parameter_name" {
  description = "SSM parameter selecting the image tag to deploy."
  value       = module.compute.image_tag_parameter_name
}

output "vpc_id" {
  description = "VPC ID."
  value       = module.network.vpc_id
}

output "db_identifier" {
  description = "RDS instance identifier."
  value       = module.database.identifier
}

output "db_master_secret_arn" {
  description = "ARN (not value) of the RDS-managed master credential secret."
  value       = module.database.master_secret_arn
}

output "app_secret_arn" {
  description = "ARN (not value) of the application API token secret."
  value       = module.security.app_secret_arn
}

output "data_kms_key_arn" {
  description = "Data encryption key."
  value       = module.security.data_kms_key_arn
}

output "logs_kms_key_arn" {
  description = "Log encryption key."
  value       = module.security.logs_kms_key_arn
}

output "cloudtrail_arn" {
  description = "Audit trail."
  value       = module.logging.cloudtrail_arn
}

output "deployment_role_arn" {
  description = "Set as the AWS_DEPLOY_ROLE_ARN variable of the GitHub 'dev' environment."
  value       = module.iam.deployment_role_arn
}

output "monitoring_role_arn" {
  description = "Read-only observability role (MFA required)."
  value       = module.iam.monitoring_role_arn
}

output "security_audit_role_arn" {
  description = "Read-only security audit role (MFA required)."
  value       = module.iam.security_audit_role_arn
}

output "alarm_topic_arn" {
  description = "SNS topic for security alarms."
  value       = module.monitoring.alarm_topic_arn
}

output "alarm_names" {
  description = "All CloudWatch alarms."
  value       = module.monitoring.alarm_names
}
