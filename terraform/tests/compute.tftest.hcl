mock_provider "aws" {
  source = "./tests/mocks"
}

variables {
  name                     = "sci-test"
  account_id               = "111122223333"
  region                   = "us-east-1"
  vpc_id                   = "vpc-0123456789abcdef0"
  public_subnet_ids        = ["subnet-p1", "subnet-p2"]
  app_subnet_ids           = ["subnet-a1", "subnet-a2"]
  alb_security_group_id    = "sg-alb"
  app_security_group_id    = "sg-app"
  app_port                 = 8443
  instance_type            = "t3.micro"
  asg_min_size             = 1
  asg_max_size             = 2
  asg_desired_capacity     = 1
  instance_profile_arn     = "arn:aws:iam::111122223333:instance-profile/sci-test-app"
  autoscaling_slr_arn      = "arn:aws:iam::111122223333:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling_sci-test"
  data_kms_key_arn         = "arn:aws:kms:us-east-1:111122223333:key/data"
  logs_kms_key_arn         = "arn:aws:kms:us-east-1:111122223333:key/logs"
  app_secret_arn           = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sci-test/app/api-token-AbCdEf"
  db_secret_arn            = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-AbCdEf"
  db_address               = "sci-test-db.abc.us-east-1.rds.amazonaws.com"
  db_port                  = 5432
  db_name                  = "app"
  app_log_group_name       = "/sci-test/app"
  alb_logs_bucket          = "sci-test-alb-logs"
  ecr_repository_name      = "sci-test-app"
  asg_name                 = "sci-test-app"
  image_tag_parameter_name = "/sci-test/app/image-tag"
  app_image_tag            = "initial"
  certificate_domain       = "app.sci.internal"
  alb_deletion_protection  = true
  enable_waf               = true
  waf_rate_limit           = 1000
  log_retention_days       = 365
}

run "compute_hardening" {
  command = apply

  module {
    source = "./modules/compute"
  }

  assert {
    condition     = aws_launch_template.app.metadata_options[0].http_tokens == "required" && aws_launch_template.app.metadata_options[0].http_put_response_hop_limit == 1
    error_message = "IMDSv2 must be enforced with hop limit 1"
  }

  assert {
    condition     = aws_launch_template.app.network_interfaces[0].associate_public_ip_address == "false"
    error_message = "application instances must not get public IPs"
  }

  assert {
    condition     = aws_launch_template.app.block_device_mappings[0].ebs[0].encrypted == "true" && aws_launch_template.app.block_device_mappings[0].ebs[0].kms_key_id == var.data_kms_key_arn
    error_message = "EBS volumes must be encrypted with the data CMK"
  }

  assert {
    condition     = aws_launch_template.app.key_name == null
    error_message = "no SSH key pair may be attached (access is via SSM Session Manager)"
  }

  assert {
    condition     = !strcontains(base64decode(aws_launch_template.app.user_data), "PASSWORD=") && !strcontains(base64decode(aws_launch_template.app.user_data), "APP_API_TOKEN=")
    error_message = "user data must pass secret ARNs, never secret values"
  }

  assert {
    condition     = aws_autoscaling_group.app.vpc_zone_identifier == toset(var.app_subnet_ids)
    error_message = "instances must run in the private app subnets"
  }

  assert {
    condition     = aws_lb_listener.https.protocol == "HTTPS" && aws_lb_listener.https.port == 443 && aws_lb_listener.https.ssl_policy == "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"
    error_message = "the only listener must be HTTPS/443 with a TLS1.2+ restricted policy"
  }

  assert {
    condition     = aws_lb_target_group.app.protocol == "HTTPS" && aws_lb_target_group.app.health_check[0].protocol == "HTTPS"
    error_message = "ALB to target traffic must be re-encrypted"
  }

  assert {
    condition     = aws_lb.this.drop_invalid_header_fields && aws_lb.this.desync_mitigation_mode == "strictest" && aws_lb.this.access_logs[0].enabled
    error_message = "ALB must drop invalid headers, use strictest desync mitigation and log access"
  }

  assert {
    condition     = length(aws_wafv2_web_acl_association.alb) == 1 && length(aws_wafv2_web_acl_logging_configuration.this) == 1
    error_message = "WAF must be associated and logging"
  }

  assert {
    condition     = contains([for r in aws_wafv2_web_acl.this[0].rule : r.name], "aws-known-bad-inputs") && contains([for r in aws_wafv2_web_acl.this[0].rule : r.name], "per-ip-rate-limit")
    error_message = "WAF must include known-bad-inputs and rate limiting"
  }

  assert {
    condition     = aws_ecr_repository.app.image_tag_mutability == "IMMUTABLE" && aws_ecr_repository.app.image_scanning_configuration[0].scan_on_push && aws_ecr_repository.app.encryption_configuration[0].encryption_type == "KMS"
    error_message = "ECR must be immutable, scan on push and use KMS"
  }

  assert {
    condition     = aws_ecr_repository.app.force_delete == false
    error_message = "the image repository must not be force-deletable by default"
  }

  assert {
    condition     = aws_cloudwatch_log_group.waf[0].kms_key_id == var.logs_kms_key_arn
    error_message = "WAF logs must be KMS-encrypted"
  }
}

run "self_signed_cert_only_without_acm_cert" {
  command = plan

  module {
    source = "./modules/compute"
  }

  variables {
    certificate_arn = "arn:aws:acm:us-east-1:111122223333:certificate/real"
  }

  assert {
    condition     = length(aws_acm_certificate.self_signed) == 0 && aws_lb_listener.https.certificate_arn == var.certificate_arn
    error_message = "a supplied ACM certificate must be used instead of generating one"
  }
}
