# PostgreSQL in private DB subnets.
#  * publicly_accessible = false, DB subnets have no internet route, the
#    security group admits only the app tier, and the NACL denies the rest.
#  * Storage, snapshots, Performance Insights and the master secret are
#    encrypted with the customer-managed data key.
#  * The master password is generated, stored and rotated by RDS in Secrets
#    Manager (manage_master_user_password); it never appears in code or state.
#  * rds.force_ssl=1 rejects unencrypted client connections.
#  * Connection/disconnection and authentication-failure logs are exported to
#    KMS-encrypted CloudWatch log groups for alerting.

resource "aws_db_subnet_group" "this" {
  name        = "${var.identifier}-subnets"
  description = "Private database subnets for ${var.identifier}"
  subnet_ids  = var.subnet_ids
}

resource "aws_db_parameter_group" "this" {
  name        = "${var.identifier}-pg${var.engine_version}"
  family      = "postgres${var.engine_version}"
  description = "Hardened parameters for ${var.identifier}"

  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  parameter {
    name  = "password_encryption"
    value = "scram-sha-256"
  }

  parameter {
    name  = "log_statement"
    value = "ddl"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Pre-create the export log groups so they are KMS-encrypted and retained;
# otherwise RDS would create them unencrypted with infinite retention.
resource "aws_cloudwatch_log_group" "postgresql" {
  name              = "/aws/rds/instance/${var.identifier}/postgresql"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.logs_kms_key_arn
}

resource "aws_cloudwatch_log_group" "upgrade" {
  name              = "/aws/rds/instance/${var.identifier}/upgrade"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.logs_kms_key_arn
}

#---------------------------------------------- enhanced monitoring role
data "aws_iam_policy_document" "monitoring_trust" {
  statement {
    sid     = "RdsMonitoringAssume"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_iam_role" "rds_monitoring" {
  name                 = "${var.identifier}-enhanced-monitoring"
  description          = "Lets RDS publish OS-level Enhanced Monitoring metrics for ${var.identifier}"
  assume_role_policy   = data.aws_iam_policy_document.monitoring_trust.json
  max_session_duration = 3600
}

# Equivalent to the AWS managed AmazonRDSEnhancedMonitoringRole, but scoped to
# this account and region instead of every region.
data "aws_iam_policy_document" "rds_monitoring" {
  statement {
    sid       = "ManageRdsOsMetricsLogGroup"
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:PutRetentionPolicy"]
    resources = ["arn:${var.partition}:logs:${var.region}:${var.account_id}:log-group:RDSOSMetrics"]
  }

  statement {
    sid    = "WriteRdsOsMetrics"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:DescribeLogStreams",
      "logs:GetLogEvents",
      "logs:PutLogEvents",
    ]
    resources = ["arn:${var.partition}:logs:${var.region}:${var.account_id}:log-group:RDSOSMetrics:log-stream:*"]
  }
}

resource "aws_iam_role_policy" "rds_monitoring" {
  name   = "publish-enhanced-monitoring"
  role   = aws_iam_role.rds_monitoring.id
  policy = data.aws_iam_policy_document.rds_monitoring.json
}

#---------------------------------------------------------- instance
resource "aws_db_instance" "this" {
  #checkov:skip=CKV_AWS_157:Multi-AZ is an availability (not confidentiality) control and doubles cost; exposed as var.db_multi_az, enable for production.
  identifier     = var.identifier
  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.instance_class
  db_name        = var.db_name
  port           = var.db_port

  username                      = var.master_username
  manage_master_user_password   = true
  master_user_secret_kms_key_id = var.data_kms_key_arn

  allocated_storage = var.allocated_storage
  storage_type      = "gp3"
  storage_encrypted = true
  kms_key_id        = var.data_kms_key_arn

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [var.security_group_id]
  publicly_accessible    = false
  network_type           = "IPV4"
  multi_az               = var.multi_az
  parameter_group_name   = aws_db_parameter_group.this.name
  ca_cert_identifier     = "rds-ca-rsa2048-g1"

  iam_database_authentication_enabled = true

  backup_retention_period   = var.backup_retention_days
  backup_window             = "03:00-04:00"
  maintenance_window        = "sun:04:30-sun:05:30"
  copy_tags_to_snapshot     = true
  delete_automated_backups  = true
  deletion_protection       = var.deletion_protection
  skip_final_snapshot       = var.skip_final_snapshot
  final_snapshot_identifier = "${var.identifier}-final"

  auto_minor_version_upgrade  = true
  allow_major_version_upgrade = false
  apply_immediately           = false

  enabled_cloudwatch_logs_exports       = ["postgresql", "upgrade"]
  monitoring_interval                   = 60
  monitoring_role_arn                   = aws_iam_role.rds_monitoring.arn
  performance_insights_enabled          = var.performance_insights
  performance_insights_kms_key_id       = var.performance_insights ? var.data_kms_key_arn : null
  performance_insights_retention_period = var.performance_insights ? 7 : null

  depends_on = [
    aws_cloudwatch_log_group.postgresql,
    aws_cloudwatch_log_group.upgrade,
    aws_iam_role_policy.rds_monitoring,
  ]
}
