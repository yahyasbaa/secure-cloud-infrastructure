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

variable "vpc_id" {
  description = "VPC ID."
  type        = string
}

variable "public_subnet_ids" {
  description = "Subnets for the load balancer."
  type        = list(string)
}

variable "app_subnet_ids" {
  description = "Private subnets for application instances."
  type        = list(string)
}

variable "alb_security_group_id" {
  description = "Load balancer security group."
  type        = string
}

variable "app_security_group_id" {
  description = "Application security group."
  type        = string
}

variable "app_port" {
  description = "Application TLS port."
  type        = number
}

variable "instance_type" {
  description = "EC2 instance type."
  type        = string
}

variable "ami_id" {
  description = "Explicit AMI (null = latest Amazon Linux 2023)."
  type        = string
  default     = null
}

variable "asg_min_size" {
  description = "ASG minimum size."
  type        = number
}

variable "asg_max_size" {
  description = "ASG maximum size."
  type        = number
}

variable "asg_desired_capacity" {
  description = "ASG desired capacity."
  type        = number
}

variable "instance_profile_arn" {
  description = "Instance profile for application hosts."
  type        = string
}

variable "autoscaling_slr_arn" {
  description = "Auto Scaling service-linked role trusted by the data key."
  type        = string
}

variable "data_kms_key_arn" {
  description = "KMS key for EBS and ECR."
  type        = string
}

variable "logs_kms_key_arn" {
  description = "KMS key for WAF logs."
  type        = string
}

variable "app_secret_arn" {
  description = "API token secret ARN (passed to the container as an ARN, never a value)."
  type        = string
}

variable "db_secret_arn" {
  description = "DB credential secret ARN (passed as an ARN, never a value)."
  type        = string
}

variable "db_address" {
  description = "Database hostname."
  type        = string
}

variable "db_port" {
  description = "Database port."
  type        = number
}

variable "db_name" {
  description = "Database name."
  type        = string
}

variable "app_log_group_name" {
  description = "Application log group."
  type        = string
}

variable "alb_logs_bucket" {
  description = "Bucket for ALB access and connection logs."
  type        = string
}

variable "ecr_repository_name" {
  description = "ECR repository name."
  type        = string
}

variable "ecr_force_delete" {
  description = "Allow deleting the repository while it still contains images (teardown only)."
  type        = bool
  default     = false
}

variable "asg_name" {
  description = "Auto Scaling group name."
  type        = string
}

variable "image_tag_parameter_name" {
  description = "SSM parameter with the image tag to run."
  type        = string
}

variable "app_image_tag" {
  description = "Initial image tag."
  type        = string
}

variable "certificate_arn" {
  description = "ACM certificate (null = generate self-signed)."
  type        = string
  default     = null
}

variable "certificate_domain" {
  description = "Domain for the self-signed certificate."
  type        = string
}

variable "alb_deletion_protection" {
  description = "ALB deletion protection."
  type        = bool
}

variable "enable_waf" {
  description = "Attach WAF."
  type        = bool
}

variable "waf_rate_limit" {
  description = "Per-IP request limit per 5 minutes."
  type        = number
}

variable "log_retention_days" {
  description = "WAF log retention."
  type        = number
}

variable "root_volume_size" {
  description = "Root EBS volume size in GiB."
  type        = number
  default     = 20
}
