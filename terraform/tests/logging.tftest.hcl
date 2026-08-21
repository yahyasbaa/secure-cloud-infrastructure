mock_provider "aws" {
  source = "./tests/mocks"
}

variables {
  name                      = "sci-test"
  account_id                = "111122223333"
  partition                 = "aws"
  region                    = "us-east-1"
  trail_name                = "sci-test-trail"
  logs_kms_key_arn          = "arn:aws:kms:us-east-1:111122223333:key/logs"
  log_retention_days        = 365
  log_bucket_retention_days = 365
  force_destroy_buckets     = false
}

run "audit_logging" {
  command = apply

  module {
    source = "./modules/logging"
  }

  assert {
    condition     = aws_cloudtrail.this.is_multi_region_trail && aws_cloudtrail.this.include_global_service_events && aws_cloudtrail.this.enable_logging
    error_message = "CloudTrail must be enabled, multi-region and include global services"
  }

  assert {
    condition     = aws_cloudtrail.this.enable_log_file_validation
    error_message = "CloudTrail log file validation must be on"
  }

  assert {
    condition     = aws_cloudtrail.this.kms_key_id == var.logs_kms_key_arn
    error_message = "CloudTrail must encrypt with the logs CMK"
  }

  assert {
    condition     = aws_cloudtrail.this.cloud_watch_logs_group_arn != null && aws_cloudtrail.this.cloud_watch_logs_role_arn != null
    error_message = "CloudTrail must stream to CloudWatch Logs for alerting"
  }

  assert {
    condition     = aws_cloudtrail.this.event_selector[0].read_write_type == "All" && aws_cloudtrail.this.event_selector[0].include_management_events
    error_message = "CloudTrail must record read and write management events"
  }

  assert {
    condition     = alltrue([for g in [aws_cloudwatch_log_group.app, aws_cloudwatch_log_group.flow_logs, aws_cloudwatch_log_group.cloudtrail] : g.kms_key_id == var.logs_kms_key_arn && g.retention_in_days == 365])
    error_message = "every log group must be KMS-encrypted and have a retention period"
  }

  assert {
    condition = alltrue([for p in [aws_s3_bucket_public_access_block.access_logs, aws_s3_bucket_public_access_block.cloudtrail, aws_s3_bucket_public_access_block.alb_logs] :
    p.block_public_acls && p.block_public_policy && p.ignore_public_acls && p.restrict_public_buckets])
    error_message = "every bucket must block all public access"
  }

  assert {
    condition     = alltrue([for v in [aws_s3_bucket_versioning.access_logs, aws_s3_bucket_versioning.cloudtrail, aws_s3_bucket_versioning.alb_logs] : v.versioning_configuration[0].status == "Enabled"])
    error_message = "every bucket must be versioned"
  }

  assert {
    condition     = alltrue([for o in [aws_s3_bucket_ownership_controls.access_logs, aws_s3_bucket_ownership_controls.cloudtrail, aws_s3_bucket_ownership_controls.alb_logs] : o.rule[0].object_ownership == "BucketOwnerEnforced"])
    error_message = "ACLs must be disabled on every bucket"
  }

  assert {
    condition     = one(aws_s3_bucket_server_side_encryption_configuration.cloudtrail.rule).apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms"
    error_message = "the CloudTrail bucket must use SSE-KMS"
  }

  assert {
    condition = alltrue([for e in [aws_s3_bucket_server_side_encryption_configuration.access_logs, aws_s3_bucket_server_side_encryption_configuration.alb_logs] :
    one(e.rule).apply_server_side_encryption_by_default[0].sse_algorithm == "AES256"])
    error_message = "log-delivery buckets must at least use SSE-S3"
  }

  assert {
    condition     = aws_s3_bucket.cloudtrail.force_destroy == false && aws_s3_bucket.alb_logs.force_destroy == false && aws_s3_bucket.access_logs.force_destroy == false
    error_message = "log buckets must not be force-destroyable by default"
  }
}
