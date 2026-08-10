variable "name" {
  description = "Name prefix for all resources."
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

variable "trail_name" {
  description = "Name of the CloudTrail trail allowed to use the logs key."
  type        = string
}

variable "log_group_prefixes" {
  description = "CloudWatch log group name prefixes allowed to use the logs key."
  type        = list(string)
}

variable "app_token_version" {
  description = "Bump to rotate the application API token through Terraform."
  type        = number
}

variable "secret_recovery_window_days" {
  description = "Days a deleted secret can be recovered (0 = delete immediately; teardown only)."
  type        = number
  default     = 7
}

variable "key_deletion_window_days" {
  description = "Waiting period before a scheduled KMS key deletion completes."
  type        = number
  default     = 30

  validation {
    condition     = var.key_deletion_window_days >= 7 && var.key_deletion_window_days <= 30
    error_message = "key_deletion_window_days must be between 7 and 30."
  }
}
