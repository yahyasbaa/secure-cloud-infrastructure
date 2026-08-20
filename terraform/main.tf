data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

# Zones are pinned by name so the subnet layout never shifts when AWS adds an
# Availability Zone; the data source fails the plan if a pinned zone is not
# available to this account.
locals {
  requested_azs = coalesce(var.availability_zones, [for s in slice(["a", "b", "c"], 0, var.az_count) : "${var.aws_region}${s}"])
}

data "aws_availability_zones" "available" {
  state = "available"

  filter {
    name   = "zone-name"
    values = local.requested_azs
  }
}

locals {
  name       = "${var.project}-${var.environment}"
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region
  azs        = sort(data.aws_availability_zones.available.names)

  db_identifier = "${local.name}-db"
  trail_name    = "${local.name}-trail"

  # Every CloudWatch log group in the stack. The logs KMS key policy only lets
  # CloudWatch Logs use the key for log groups matching these names.
  log_group_prefixes = [
    "/${local.name}/",
    "/aws/rds/instance/${local.db_identifier}/",
    "aws-waf-logs-${local.name}",
  ]

  operator_principal_arns = length(var.operator_principal_arns) > 0 ? var.operator_principal_arns : [
    "arn:${local.partition}:iam::${local.account_id}:root"
  ]
}

# Cryptographic foundation: KMS keys, application secret, service-linked role
# that the data key policy must reference.
module "security" {
  source = "./modules/security"

  name                        = local.name
  account_id                  = local.account_id
  partition                   = local.partition
  region                      = local.region
  trail_name                  = local.trail_name
  log_group_prefixes          = local.log_group_prefixes
  app_token_version           = var.app_token_version
  secret_recovery_window_days = var.allow_force_destroy ? 0 : 7
}

module "network" {
  source = "./modules/network"

  name                        = local.name
  account_id                  = local.account_id
  partition                   = local.partition
  flow_log_group_arn          = module.logging.flow_logs_log_group_arn
  region                      = local.region
  vpc_cidr                    = var.vpc_cidr
  azs                         = local.azs
  interface_endpoint_az_count = var.interface_endpoint_az_count
  alb_ingress_cidrs           = var.alb_ingress_cidrs
  app_port                    = var.app_port
  db_port                     = var.db_port
}

module "logging" {
  source = "./modules/logging"

  name                      = local.name
  account_id                = local.account_id
  partition                 = local.partition
  region                    = local.region
  trail_name                = local.trail_name
  logs_kms_key_arn          = module.security.logs_kms_key_arn
  log_retention_days        = var.log_retention_days
  log_bucket_retention_days = var.log_bucket_retention_days
  force_destroy_buckets     = var.allow_force_destroy
}

module "database" {
  source = "./modules/database"

  identifier            = local.db_identifier
  account_id            = local.account_id
  partition             = local.partition
  region                = local.region
  subnet_ids            = module.network.db_subnet_ids
  security_group_id     = module.network.db_security_group_id
  db_port               = var.db_port
  engine_version        = var.db_engine_version
  instance_class        = var.db_instance_class
  allocated_storage     = var.db_allocated_storage
  multi_az              = var.db_multi_az
  backup_retention_days = var.db_backup_retention_days
  deletion_protection   = var.db_deletion_protection
  skip_final_snapshot   = var.db_skip_final_snapshot
  performance_insights  = var.db_performance_insights
  data_kms_key_arn      = module.security.data_kms_key_arn
  logs_kms_key_arn      = module.security.logs_kms_key_arn
  log_retention_days    = var.log_retention_days
}

module "iam" {
  source = "./modules/iam"

  name                        = local.name
  account_id                  = local.account_id
  partition                   = local.partition
  region                      = local.region
  github_repository           = var.github_repository
  github_environment          = var.github_environment
  create_github_oidc_provider = var.create_github_oidc_provider
  operator_principal_arns     = local.operator_principal_arns

  data_kms_key_arn         = module.security.data_kms_key_arn
  logs_kms_key_arn         = module.security.logs_kms_key_arn
  app_secret_arn           = module.security.app_secret_arn
  db_secret_arn            = module.database.master_secret_arn
  db_instance_arn          = module.database.instance_arn
  app_log_group_arn        = module.logging.app_log_group_arn
  readable_log_group_arns  = concat(module.logging.log_group_arns, module.database.log_group_arns)
  cloudtrail_arn           = module.logging.cloudtrail_arn
  cloudtrail_log_group_arn = module.logging.cloudtrail_log_group_arn
  log_bucket_arns          = module.logging.bucket_arns
  ecr_repository_name      = "${local.name}-app"
  asg_arn                  = module.compute.asg_arn
  alarm_arns               = module.monitoring.alarm_arns
  image_tag_parameter_name = "/${local.name}/app/image-tag"
  service_role_arns        = [module.network.flow_logs_role_arn, module.logging.cloudtrail_role_arn, module.database.monitoring_role_arn]
}

module "compute" {
  source = "./modules/compute"

  name                     = local.name
  account_id               = local.account_id
  region                   = local.region
  vpc_id                   = module.network.vpc_id
  public_subnet_ids        = module.network.public_subnet_ids
  app_subnet_ids           = module.network.app_subnet_ids
  alb_security_group_id    = module.network.alb_security_group_id
  app_security_group_id    = module.network.app_security_group_id
  app_port                 = var.app_port
  instance_type            = var.instance_type
  ami_id                   = var.ami_id
  asg_min_size             = var.asg_min_size
  asg_max_size             = var.asg_max_size
  asg_desired_capacity     = var.asg_desired_capacity
  instance_profile_arn     = module.iam.app_instance_profile_arn
  autoscaling_slr_arn      = module.security.autoscaling_service_linked_role_arn
  data_kms_key_arn         = module.security.data_kms_key_arn
  logs_kms_key_arn         = module.security.logs_kms_key_arn
  app_secret_arn           = module.security.app_secret_arn
  db_secret_arn            = module.database.master_secret_arn
  db_address               = module.database.address
  db_port                  = var.db_port
  db_name                  = module.database.db_name
  app_log_group_name       = module.logging.app_log_group_name
  alb_logs_bucket          = module.logging.alb_logs_bucket
  ecr_repository_name      = "${local.name}-app"
  ecr_force_delete         = var.allow_force_destroy
  asg_name                 = "${local.name}-app"
  image_tag_parameter_name = "/${local.name}/app/image-tag"
  app_image_tag            = var.app_image_tag
  certificate_arn          = var.certificate_arn
  certificate_domain       = var.certificate_domain
  alb_deletion_protection  = var.alb_deletion_protection
  enable_waf               = var.enable_waf
  waf_rate_limit           = var.waf_rate_limit
  log_retention_days       = var.log_retention_days
}

module "monitoring" {
  source = "./modules/monitoring"

  name                      = local.name
  account_id                = local.account_id
  logs_kms_key_arn          = module.security.logs_kms_key_arn
  alarm_email               = var.alarm_email
  enable_guardduty          = var.enable_guardduty
  cloudtrail_log_group_name = module.logging.cloudtrail_log_group_name
  app_log_group_name        = module.logging.app_log_group_name
  db_log_group_name         = module.database.postgresql_log_group_name
  app_role_name             = module.iam.app_role_name
  alb_arn_suffix            = module.compute.alb_arn_suffix
  target_group_arn_suffix   = module.compute.target_group_arn_suffix
  waf_web_acl_name          = module.compute.waf_web_acl_name
  region                    = local.region
  db_identifier             = module.database.identifier
}
