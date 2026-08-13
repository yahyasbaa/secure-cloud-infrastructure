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
  description = "CloudTrail trail name."
  type        = string
}

variable "logs_kms_key_arn" {
  description = "KMS key for log encryption."
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch log retention."
  type        = number
}

variable "log_bucket_retention_days" {
  description = "Days before log objects expire."
  type        = number
}

variable "force_destroy_buckets" {
  description = "Allow destroying non-empty buckets."
  type        = bool
}
