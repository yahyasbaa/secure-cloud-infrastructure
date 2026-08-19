# Security alarms. Every alarm is documented in docs/monitoring.md
# (tests/security/test_documentation.py fails if one is missing).
#
# Log-based detections use CloudWatch Logs metric filters; patterns for the
# CloudTrail group follow the CIS AWS Foundations Benchmark (section 4/5).

locals {
  namespace = "SCI/Security"

  log_alarms = {
    "unauthorized-api-calls" = {
      log_group   = var.cloudtrail_log_group_name
      pattern     = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
      threshold   = 5
      description = "5+ AccessDenied/UnauthorizedOperation API errors in 5 minutes: credential misuse, privilege probing or a broken deployment."
    }
    "console-signin-failures" = {
      log_group   = var.cloudtrail_log_group_name
      pattern     = "{ ($.eventName = \"ConsoleLogin\") && ($.errorMessage = \"Failed authentication\") }"
      threshold   = 3
      description = "3+ failed AWS console sign-ins in 5 minutes: possible password guessing."
    }
    "console-signin-without-mfa" = {
      log_group   = var.cloudtrail_log_group_name
      pattern     = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.userIdentity.type = \"IAMUser\") && ($.responseElements.ConsoleLogin = \"Success\") }"
      threshold   = 1
      description = "Successful console sign-in by an IAM user without MFA."
    }
    "root-account-usage" = {
      log_group   = var.cloudtrail_log_group_name
      pattern     = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
      threshold   = 1
      description = "The root user was used. Root should be locked away; any use must be investigated."
    }
    "iam-policy-changes" = {
      log_group   = var.cloudtrail_log_group_name
      pattern     = "{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = SetDefaultPolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy) || ($.eventName = UpdateAssumeRolePolicy) }"
      threshold   = 1
      description = "An IAM policy or trust policy was created, changed, attached or detached (possible privilege escalation)."
    }
    "security-group-changes" = {
      log_group   = var.cloudtrail_log_group_name
      pattern     = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) || ($.eventName = ModifySecurityGroupRules) }"
      threshold   = 1
      description = "A security group or rule was created, modified or deleted (possible exposure of a private tier)."
    }
    "nacl-changes" = {
      log_group   = var.cloudtrail_log_group_name
      pattern     = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
      threshold   = 1
      description = "A network ACL or ACL entry changed."
    }
    "network-gateway-changes" = {
      log_group   = var.cloudtrail_log_group_name
      pattern     = "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) || ($.eventName = CreateNatGateway) || ($.eventName = DeleteNatGateway) }"
      threshold   = 1
      description = "An internet, NAT or customer gateway changed (new egress/ingress path)."
    }
    "route-table-changes" = {
      log_group   = var.cloudtrail_log_group_name
      pattern     = "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"
      threshold   = 1
      description = "A route or route table changed (could give private subnets an internet path)."
    }
    "vpc-changes" = {
      log_group   = var.cloudtrail_log_group_name
      pattern     = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"
      threshold   = 1
      description = "A VPC, VPC attribute or peering connection changed."
    }
    "cloudtrail-changes" = {
      log_group   = var.cloudtrail_log_group_name
      pattern     = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) || ($.eventName = PutEventSelectors) }"
      threshold   = 1
      description = "CloudTrail configuration changed (attackers disable logging to cover tracks)."
    }
    "kms-key-disable-or-deletion" = {
      log_group   = var.cloudtrail_log_group_name
      pattern     = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion) || ($.eventName = PutKeyPolicy)) }"
      threshold   = 1
      description = "A KMS key was disabled, scheduled for deletion, or had its policy replaced (ransom / denial of access to data)."
    }
    "s3-bucket-policy-changes" = {
      log_group   = var.cloudtrail_log_group_name
      pattern     = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication) || ($.eventName = PutBucketPublicAccessBlock) || ($.eventName = DeleteBucketPublicAccessBlock)) }"
      threshold   = 1
      description = "An S3 bucket policy, ACL, public-access block or replication rule changed (possible exposure or exfiltration)."
    }
    "unexpected-secret-access" = {
      log_group   = var.cloudtrail_log_group_name
      pattern     = "{ ($.eventSource = \"secretsmanager.amazonaws.com\") && ($.eventName = \"GetSecretValue\") && ($.userIdentity.type != \"AWSService\") && ($.userIdentity.arn != \"*:assumed-role/${var.app_role_name}/*\") }"
      threshold   = 1
      description = "A secret value was read by a principal other than the application role (unusual access pattern / insider or stolen credential)."
    }
    "app-auth-failures" = {
      log_group   = var.app_log_group_name
      pattern     = "{ $.event = \"auth_failure\" }"
      threshold   = 10
      description = "10+ rejected API tokens in 5 minutes: brute force or credential stuffing against the API."
    }
    "app-unhandled-errors" = {
      log_group   = var.app_log_group_name
      pattern     = "{ $.event = \"unhandled_error\" }"
      threshold   = 5
      description = "5+ unhandled application errors in 5 minutes: possible exploitation attempt or outage."
    }
    "db-auth-failures" = {
      log_group   = var.db_log_group_name
      pattern     = "?\"password authentication failed\" ?\"no pg_hba.conf entry\""
      threshold   = 5
      description = "5+ PostgreSQL authentication failures in 5 minutes: password guessing or a compromised host using stale credentials."
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "security" {
  for_each = local.log_alarms

  name           = "${var.name}-${each.key}"
  log_group_name = each.value.log_group
  pattern        = each.value.pattern

  metric_transformation {
    name          = each.key
    namespace     = local.namespace
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "security" {
  for_each = local.log_alarms

  alarm_name          = "${var.name}-${each.key}"
  alarm_description   = each.value.description
  namespace           = local.namespace
  metric_name         = each.key
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]

  depends_on = [aws_cloudwatch_log_metric_filter.security]
}

#------------------------------------------------- unusual access patterns
# Anomaly detection learns the normal request profile of the load balancer
# and the normal rate of authorization failures, and alarms on deviations
# that fixed thresholds would miss (e.g. slow scraping, off-hours probing).
resource "aws_cloudwatch_metric_alarm" "alb_request_anomaly" {
  alarm_name          = "${var.name}-alb-request-anomaly"
  alarm_description   = "Request volume to the load balancer is outside the learned normal band (scraping, scanning, DDoS)."
  comparison_operator = "GreaterThanUpperThreshold"
  evaluation_periods  = 3
  threshold_metric_id = "band"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]

  metric_query {
    id          = "band"
    expression  = "ANOMALY_DETECTION_BAND(requests, 3)"
    label       = "RequestCount (expected)"
    return_data = true
  }

  metric_query {
    id          = "requests"
    return_data = true
    metric {
      namespace   = "AWS/ApplicationELB"
      metric_name = "RequestCount"
      period      = 300
      stat        = "Sum"
      dimensions  = { LoadBalancer = var.alb_arn_suffix }
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api_anomaly" {
  alarm_name          = "${var.name}-unauthorized-api-anomaly"
  alarm_description   = "Rate of denied API calls deviates from its learned baseline (reconnaissance with stolen credentials)."
  comparison_operator = "GreaterThanUpperThreshold"
  evaluation_periods  = 2
  threshold_metric_id = "band"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]

  metric_query {
    id          = "band"
    expression  = "ANOMALY_DETECTION_BAND(denied, 2)"
    label       = "Denied API calls (expected)"
    return_data = true
  }

  metric_query {
    id          = "denied"
    return_data = true
    metric {
      namespace   = local.namespace
      metric_name = "unauthorized-api-calls"
      period      = 300
      stat        = "Sum"
    }
  }

  depends_on = [aws_cloudwatch_log_metric_filter.security]
}

#--------------------------------------------------------- service health
resource "aws_cloudwatch_metric_alarm" "waf_blocked_spike" {
  count               = var.waf_web_acl_name == null ? 0 : 1
  alarm_name          = "${var.name}-waf-blocked-spike"
  alarm_description   = "WAF blocked 100+ requests in 5 minutes: active attack or scanning against the application."
  namespace           = "AWS/WAFV2"
  metric_name         = "BlockedRequests"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 100
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  dimensions = {
    WebACL = var.waf_web_acl_name
    Region = var.region
    Rule   = "ALL"
  }
}

resource "aws_cloudwatch_metric_alarm" "alb_5xx" {
  alarm_name          = "${var.name}-alb-5xx"
  alarm_description   = "Load balancer returned 10+ 5xx responses in 5 minutes."
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_ELB_5XX_Count"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  dimensions          = { LoadBalancer = var.alb_arn_suffix }
}

resource "aws_cloudwatch_metric_alarm" "unhealthy_hosts" {
  alarm_name          = "${var.name}-unhealthy-hosts"
  alarm_description   = "At least one application target failed health checks for 10 minutes."
  namespace           = "AWS/ApplicationELB"
  metric_name         = "UnHealthyHostCount"
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  dimensions = {
    LoadBalancer = var.alb_arn_suffix
    TargetGroup  = var.target_group_arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "db_cpu" {
  alarm_name          = "${var.name}-db-cpu-high"
  alarm_description   = "Database CPU above 80% for 15 minutes (load, runaway query, or abuse such as crypto-mining via SQL)."
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "missing"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  dimensions          = { DBInstanceIdentifier = var.db_identifier }
}

resource "aws_cloudwatch_metric_alarm" "db_storage" {
  alarm_name          = "${var.name}-db-free-storage-low"
  alarm_description   = "Database free storage below 2 GiB (bulk inserts / data stuffing, or organic growth)."
  namespace           = "AWS/RDS"
  metric_name         = "FreeStorageSpace"
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 2147483648
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "missing"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  dimensions          = { DBInstanceIdentifier = var.db_identifier }
}
