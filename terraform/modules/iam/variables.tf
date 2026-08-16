variable "name" {
  description = "Name prefix."
  type        = string
}

variable "account_id" {
  description = "AWS account ID."
  type        = string
}

variable "partition" {
  description = "AWS partition."
  type        = string
}

variable "region" {
  description = "AWS region."
  type        = string
}

variable "github_repository" {
  description = "owner/name of the GitHub repository trusted for deployments."
  type        = string
}

variable "github_environment" {
  description = "GitHub environment trusted for deployments."
  type        = string
}

variable "create_github_oidc_provider" {
  description = "Create the GitHub OIDC provider (false = look up an existing one)."
  type        = bool
}

variable "operator_principal_arns" {
  description = "Principals allowed to assume the human operator roles (with MFA)."
  type        = list(string)
}

variable "data_kms_key_arn" {
  description = "Data KMS key ARN."
  type        = string
}

variable "logs_kms_key_arn" {
  description = "Logs KMS key ARN."
  type        = string
}

variable "app_secret_arn" {
  description = "Application API token secret ARN."
  type        = string
}

variable "db_secret_arn" {
  description = "RDS-managed master secret ARN."
  type        = string
}

variable "db_instance_arn" {
  description = "RDS instance ARN."
  type        = string
}

variable "app_log_group_arn" {
  description = "Application log group ARN."
  type        = string
}

variable "readable_log_group_arns" {
  description = "Log groups the monitoring role may read."
  type        = list(string)
}

variable "alarm_arns" {
  description = "CloudWatch alarms the monitoring role may describe."
  type        = list(string)
}

variable "cloudtrail_arn" {
  description = "Trail ARN."
  type        = string
}

variable "cloudtrail_log_group_arn" {
  description = "CloudTrail log group ARN."
  type        = string
}

variable "log_bucket_arns" {
  description = "Log bucket ARNs (configuration readable by auditors)."
  type        = list(string)
}

variable "ecr_repository_name" {
  description = "ECR repository name."
  type        = string
}

variable "asg_arn" {
  description = "Auto Scaling group ARN the deployment role may roll."
  type        = string
}

variable "service_role_arns" {
  description = "Service roles defined in other modules that auditors may inspect."
  type        = list(string)
}

variable "image_tag_parameter_name" {
  description = "SSM parameter holding the deployed image tag."
  type        = string
}
