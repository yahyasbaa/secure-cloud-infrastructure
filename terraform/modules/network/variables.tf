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

variable "flow_log_group_arn" {
  description = "KMS-encrypted CloudWatch log group receiving VPC flow logs."
  type        = string
}

variable "region" {
  description = "AWS region (used for endpoint service names)."
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block."
  type        = string
}

variable "azs" {
  description = "Availability zones to use."
  type        = list(string)
}

variable "interface_endpoint_az_count" {
  description = "Number of AZs hosting interface endpoint ENIs."
  type        = number
}

variable "alb_ingress_cidrs" {
  description = "CIDRs allowed to reach the ALB on 443."
  type        = list(string)
}

variable "app_port" {
  description = "Application listener port."
  type        = number
}

variable "db_port" {
  description = "Database port."
  type        = number
}

variable "interface_endpoint_services" {
  description = "AWS services reached privately through interface endpoints (there is no NAT gateway)."
  type        = list(string)
  default     = ["ssm", "ssmmessages", "ec2messages", "secretsmanager", "logs", "ecr.api", "ecr.dkr"]
}
