variable "identifier" {
  description = "RDS instance identifier."
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

variable "subnet_ids" {
  description = "Private database subnet IDs."
  type        = list(string)
}

variable "security_group_id" {
  description = "Database security group."
  type        = string
}

variable "db_port" {
  description = "Database port."
  type        = number
}

variable "engine_version" {
  description = "PostgreSQL major version."
  type        = string
}

variable "instance_class" {
  description = "Instance class."
  type        = string
}

variable "allocated_storage" {
  description = "Storage in GiB."
  type        = number
}

variable "multi_az" {
  description = "Multi-AZ deployment."
  type        = bool
}

variable "backup_retention_days" {
  description = "Backup retention days."
  type        = number
}

variable "deletion_protection" {
  description = "Deletion protection."
  type        = bool
}

variable "skip_final_snapshot" {
  description = "Skip final snapshot."
  type        = bool
}

variable "performance_insights" {
  description = "Enable Performance Insights."
  type        = bool
}

variable "data_kms_key_arn" {
  description = "KMS key for storage, secrets and Performance Insights."
  type        = string
}

variable "logs_kms_key_arn" {
  description = "KMS key for exported database logs."
  type        = string
}

variable "log_retention_days" {
  description = "Retention for exported database logs."
  type        = number
}

variable "db_name" {
  description = "Initial database name."
  type        = string
  default     = "app"
}

variable "master_username" {
  description = "Master user name (the password is generated and managed by RDS)."
  type        = string
  default     = "sci_admin"
}
