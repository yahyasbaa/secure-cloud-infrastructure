mock_provider "aws" {
  source = "./tests/mocks"
}

variables {
  identifier            = "sci-test-db"
  account_id            = "111122223333"
  partition             = "aws"
  region                = "us-east-1"
  subnet_ids            = ["subnet-aaaa", "subnet-bbbb"]
  security_group_id     = "sg-0123456789abcdef0"
  db_port               = 5432
  engine_version        = "17"
  instance_class        = "db.t4g.micro"
  allocated_storage     = 20
  multi_az              = false
  backup_retention_days = 7
  deletion_protection   = true
  skip_final_snapshot   = false
  performance_insights  = true
  data_kms_key_arn      = "arn:aws:kms:us-east-1:111122223333:key/data"
  logs_kms_key_arn      = "arn:aws:kms:us-east-1:111122223333:key/logs"
  log_retention_days    = 365
}

run "database_hardening" {
  command = apply

  module {
    source = "./modules/database"
  }

  assert {
    condition     = aws_db_instance.this.publicly_accessible == false
    error_message = "database must not be publicly accessible"
  }

  assert {
    condition     = aws_db_instance.this.storage_encrypted && aws_db_instance.this.kms_key_id == var.data_kms_key_arn
    error_message = "database storage must be encrypted with the data CMK"
  }

  assert {
    condition     = aws_db_instance.this.manage_master_user_password == true && aws_db_instance.this.master_user_secret_kms_key_id == var.data_kms_key_arn && aws_db_instance.this.password == null
    error_message = "master password must be RDS-managed in Secrets Manager (never in code/state)"
  }

  assert {
    condition     = aws_db_instance.this.iam_database_authentication_enabled
    error_message = "IAM database authentication must be enabled"
  }

  assert {
    condition     = aws_db_instance.this.vpc_security_group_ids == toset([var.security_group_id]) && aws_db_subnet_group.this.subnet_ids == toset(var.subnet_ids)
    error_message = "database must live only in the private DB subnets behind the DB security group"
  }

  assert {
    condition     = aws_db_instance.this.backup_retention_period >= 7 && aws_db_instance.this.deletion_protection && aws_db_instance.this.copy_tags_to_snapshot
    error_message = "backups and deletion protection must be enabled"
  }

  assert {
    condition     = toset(aws_db_instance.this.enabled_cloudwatch_logs_exports) == toset(["postgresql", "upgrade"])
    error_message = "database logs must be exported to CloudWatch"
  }

  assert {
    condition     = alltrue([for g in [aws_cloudwatch_log_group.postgresql, aws_cloudwatch_log_group.upgrade] : g.kms_key_id == var.logs_kms_key_arn && g.retention_in_days == 365])
    error_message = "database log groups must be KMS-encrypted with retention"
  }

  assert {
    condition     = one([for p in aws_db_parameter_group.this.parameter : p.value if p.name == "rds.force_ssl"]) == "1"
    error_message = "rds.force_ssl must be 1 (TLS required)"
  }

  assert {
    condition     = one([for p in aws_db_parameter_group.this.parameter : p.value if p.name == "password_encryption"]) == "scram-sha-256"
    error_message = "passwords must be stored as SCRAM-SHA-256"
  }

  assert {
    condition     = aws_db_instance.this.performance_insights_kms_key_id == var.data_kms_key_arn
    error_message = "Performance Insights must be encrypted with the data CMK"
  }
}
