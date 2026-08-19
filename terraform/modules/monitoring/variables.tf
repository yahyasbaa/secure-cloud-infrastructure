variable "name" {
  description = "Name prefix."
  type        = string
}

variable "account_id" {
  description = "AWS account ID."
  type        = string
}

variable "region" {
  description = "AWS region."
  type        = string
}

variable "logs_kms_key_arn" {
  description = "KMS key encrypting the alarm topic."
  type        = string
}

variable "alarm_email" {
  description = "Optional e-mail subscriber."
  type        = string
  default     = null
}

variable "enable_guardduty" {
  description = "Enable GuardDuty."
  type        = bool
}

variable "cloudtrail_log_group_name" {
  description = "CloudTrail log group."
  type        = string
}

variable "app_log_group_name" {
  description = "Application log group."
  type        = string
}

variable "db_log_group_name" {
  description = "PostgreSQL log group."
  type        = string
}

variable "app_role_name" {
  description = "Application role name (the only expected secret reader)."
  type        = string
}

variable "alb_arn_suffix" {
  description = "ALB ARN suffix."
  type        = string
}

variable "target_group_arn_suffix" {
  description = "Target group ARN suffix."
  type        = string
}

variable "waf_web_acl_name" {
  description = "WAF web ACL name or null."
  type        = string
  default     = null
}

variable "db_identifier" {
  description = "RDS instance identifier."
  type        = string
}
