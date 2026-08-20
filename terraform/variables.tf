#------------------------------------------------------------------------------
# General
#------------------------------------------------------------------------------
variable "project" {
  description = "Short project identifier used as a name prefix."
  type        = string
  default     = "sci"

  validation {
    condition     = can(regex("^[a-z][a-z0-9]{1,9}$", var.project))
    error_message = "project must be 2-10 lowercase alphanumeric characters."
  }
}

variable "environment" {
  description = "Deployment environment name."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "test", "staging", "prod", "local"], var.environment)
    error_message = "environment must be one of dev, test, staging, prod, local."
  }
}

variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "allowed_account_ids" {
  description = "If set, Terraform refuses to operate on any other AWS account."
  type        = list(string)
  default     = null
}

variable "s3_use_path_style" {
  description = "Use path-style S3 addressing. Only needed for the local moto endpoint."
  type        = bool
  default     = false
}

variable "github_repository" {
  description = "GitHub repository (owner/name) allowed to assume the deployment role via OIDC."
  type        = string
  default     = "example-org/secure-cloud-infrastructure"

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must be in owner/name form and may not contain wildcards."
  }
}

variable "github_environment" {
  description = "GitHub Actions environment whose jobs may assume the deployment role."
  type        = string
  default     = "dev"

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+$", var.github_environment))
    error_message = "github_environment may not contain wildcards."
  }
}

variable "create_github_oidc_provider" {
  description = "Create the account-wide GitHub OIDC provider. Set false if it already exists in the account."
  type        = bool
  default     = true
}

variable "operator_principal_arns" {
  description = "IAM principals allowed to assume the monitoring and security-audit roles (MFA is always required). Defaults to the account root, i.e. any IAM principal in this account that is itself granted sts:AssumeRole."
  type        = list(string)
  default     = []
}

#------------------------------------------------------------------------------
# Network
#------------------------------------------------------------------------------
variable "vpc_cidr" {
  description = "CIDR block of the VPC."
  type        = string
  default     = "10.20.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0)) && tonumber(split("/", var.vpc_cidr)[1]) <= 20
    error_message = "vpc_cidr must be a valid IPv4 CIDR of /20 or larger."
  }
}

variable "az_count" {
  description = "Number of availability zones to spread subnets across."
  type        = number
  default     = 2

  validation {
    condition     = var.az_count >= 2 && var.az_count <= 3
    error_message = "az_count must be 2 or 3 (RDS subnet groups and ALBs need at least two AZs)."
  }
}

variable "availability_zones" {
  description = "Explicit availability zone names. Defaults to the first az_count zones (<region>a, <region>b, ...)."
  type        = list(string)
  default     = null

  validation {
    condition     = var.availability_zones == null ? true : length(var.availability_zones) >= 2
    error_message = "availability_zones must list at least two zones."
  }
}

variable "interface_endpoint_az_count" {
  description = "Number of AZs that host interface VPC endpoints. 1 halves endpoint cost for dev; use az_count for production resilience."
  type        = number
  default     = 1

  validation {
    condition     = var.interface_endpoint_az_count >= 1 && var.interface_endpoint_az_count <= 3
    error_message = "interface_endpoint_az_count must be between 1 and 3."
  }
}

variable "alb_ingress_cidrs" {
  description = "IPv4 CIDRs allowed to reach the load balancer on HTTPS (443)."
  type        = list(string)
  default     = ["0.0.0.0/0"]

  validation {
    condition     = length(var.alb_ingress_cidrs) > 0 && alltrue([for c in var.alb_ingress_cidrs : can(cidrhost(c, 0))])
    error_message = "alb_ingress_cidrs must be a non-empty list of valid IPv4 CIDRs."
  }
}

variable "app_port" {
  description = "TLS port the application listens on inside the VPC."
  type        = number
  default     = 8443
}

variable "db_port" {
  description = "PostgreSQL port."
  type        = number
  default     = 5432
}

#------------------------------------------------------------------------------
# Compute
#------------------------------------------------------------------------------
variable "instance_type" {
  description = "EC2 instance type for application hosts (t3.micro is Free Tier eligible)."
  type        = string
  default     = "t3.micro"
}

variable "ami_id" {
  description = "Explicit AMI ID. When null the latest Amazon Linux 2023 AMI is resolved from SSM."
  type        = string
  default     = null
}

variable "asg_min_size" {
  description = "Minimum number of application instances."
  type        = number
  default     = 1
}

variable "asg_max_size" {
  description = "Maximum number of application instances."
  type        = number
  default     = 2
}

variable "asg_desired_capacity" {
  description = "Desired number of application instances."
  type        = number
  default     = 1
}

variable "app_image_tag" {
  description = "Initial container image tag. Subsequent deploys update the SSM parameter from CI."
  type        = string
  default     = "initial"

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]{1,128}$", var.app_image_tag))
    error_message = "app_image_tag must be a valid image tag."
  }
}

variable "certificate_arn" {
  description = "ACM certificate ARN for the HTTPS listener. When null, a self-signed certificate is generated and imported (dev only)."
  type        = string
  default     = null
}

variable "certificate_domain" {
  description = "Common name used for the generated self-signed certificate."
  type        = string
  default     = "app.sci.internal"
}

variable "alb_deletion_protection" {
  description = "Enable deletion protection on the load balancer."
  type        = bool
  default     = true
}

variable "enable_waf" {
  description = "Attach an AWS WAFv2 web ACL (managed rule groups + rate limiting) to the load balancer."
  type        = bool
  default     = true
}

variable "waf_rate_limit" {
  description = "Maximum requests per 5 minutes from a single IP before WAF blocks it."
  type        = number
  default     = 1000
}

#------------------------------------------------------------------------------
# Database
#------------------------------------------------------------------------------
variable "db_engine_version" {
  description = "PostgreSQL major version."
  type        = string
  default     = "17"
}

variable "db_instance_class" {
  description = "RDS instance class (db.t4g.micro is Free Tier eligible)."
  type        = string
  default     = "db.t4g.micro"
}

variable "db_allocated_storage" {
  description = "Allocated storage in GiB (Free Tier covers 20)."
  type        = number
  default     = 20
}

variable "db_multi_az" {
  description = "Deploy a Multi-AZ standby (not Free Tier eligible)."
  type        = bool
  default     = false
}

variable "db_backup_retention_days" {
  description = "Automated backup retention in days."
  type        = number
  default     = 7

  validation {
    condition     = var.db_backup_retention_days >= 1 && var.db_backup_retention_days <= 35
    error_message = "db_backup_retention_days must be between 1 and 35."
  }
}

variable "db_deletion_protection" {
  description = "Enable RDS deletion protection. Must be set to false (and applied) before terraform destroy."
  type        = bool
  default     = true
}

variable "db_skip_final_snapshot" {
  description = "Skip the final snapshot on deletion. Keep false outside of disposable test environments."
  type        = bool
  default     = false
}

variable "db_performance_insights" {
  description = "Enable Performance Insights (7-day retention tier is free)."
  type        = bool
  default     = true
}

#------------------------------------------------------------------------------
# Logging / monitoring
#------------------------------------------------------------------------------
variable "log_retention_days" {
  description = "Retention for CloudWatch log groups."
  type        = number
  default     = 365

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be a value supported by CloudWatch Logs."
  }
}

variable "log_bucket_retention_days" {
  description = "Days before objects in log buckets expire."
  type        = number
  default     = 365
}

variable "allow_force_destroy" {
  description = "Teardown switch for disposable environments: lets terraform destroy empty the log buckets (removing the CloudTrail deny-delete statement), delete the ECR repository with its images, and delete secrets without the recovery window. Never enable for an environment whose data or audit trail must be kept."
  type        = bool
  default     = false
}

variable "alarm_email" {
  description = "Optional e-mail address subscribed to security alarms (subscription must be confirmed)."
  type        = string
  default     = null
}

variable "enable_guardduty" {
  description = "Enable Amazon GuardDuty and route high-severity findings to the alarm topic (30-day free trial, then billed)."
  type        = bool
  default     = false
}

#------------------------------------------------------------------------------
# Secrets
#------------------------------------------------------------------------------
variable "app_token_version" {
  description = "Increment to make Terraform generate and store a new application API token (write-only, never stored in state)."
  type        = number
  default     = 1
}
