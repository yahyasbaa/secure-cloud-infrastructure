# Offline mocks for `terraform test`. The AWS provider is never contacted.
# Computed attributes the provider validates (ARNs, IDs) get realistic values;
# policy documents render to a minimal valid JSON policy.

mock_data "aws_iam_policy_document" {
  defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

mock_data "aws_availability_zones" {
  defaults = { names = ["us-east-1a", "us-east-1b"] }
}

mock_data "aws_caller_identity" {
  defaults = { account_id = "111122223333" }
}

mock_data "aws_partition" {
  defaults = { partition = "aws" }
}

mock_data "aws_region" {
  defaults = { region = "us-east-1" }
}

mock_data "aws_ssm_parameter" {
  defaults = { value = "ami-0123456789abcdef0" }
}

mock_data "aws_elb_service_account" {
  defaults = { arn = "arn:aws:iam::127311923021:root" }
}

mock_resource "aws_kms_key" {
  defaults = { arn = "arn:aws:kms:us-east-1:111122223333:key/11111111-2222-3333-4444-555555555555" }
}

mock_resource "aws_iam_role" {
  defaults = { arn = "arn:aws:iam::111122223333:role/mock" }
}

mock_resource "aws_iam_service_linked_role" {
  defaults = { arn = "arn:aws:iam::111122223333:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling_mock" }
}

mock_resource "aws_cloudwatch_log_group" {
  defaults = { arn = "arn:aws:logs:us-east-1:111122223333:log-group:mock" }
}

mock_resource "aws_iam_instance_profile" {
  defaults = { arn = "arn:aws:iam::111122223333:instance-profile/mock" }
}

mock_resource "aws_secretsmanager_secret" {
  defaults = { arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:mock-AbCdEf" }
}

mock_resource "aws_db_instance" {
  defaults = {
    arn = "arn:aws:rds:us-east-1:111122223333:db:mock"
    master_user_secret = [{
      secret_arn    = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-mock-AbCdEf"
      kms_key_id    = "arn:aws:kms:us-east-1:111122223333:key/11111111-2222-3333-4444-555555555555"
      secret_status = "active"
    }]
  }
}

mock_resource "aws_s3_bucket" {
  defaults = { arn = "arn:aws:s3:::mock-bucket" }
}

mock_resource "aws_lb" {
  defaults = { arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/mock/0123456789abcdef" }
}

mock_resource "aws_lb_target_group" {
  defaults = { arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/mock/0123456789abcdef" }
}

mock_resource "aws_acm_certificate" {
  defaults = { arn = "arn:aws:acm:us-east-1:111122223333:certificate/11111111-2222-3333-4444-555555555555" }
}

mock_resource "aws_wafv2_web_acl" {
  defaults = { arn = "arn:aws:wafv2:us-east-1:111122223333:regional/webacl/mock/11111111-2222-3333-4444-555555555555" }
}

mock_resource "aws_sns_topic" {
  defaults = { arn = "arn:aws:sns:us-east-1:111122223333:mock" }
}

mock_resource "aws_autoscaling_group" {
  defaults = { arn = "arn:aws:autoscaling:us-east-1:111122223333:autoScalingGroup:11111111-2222-3333-4444-555555555555:autoScalingGroupName/mock" }
}

mock_resource "aws_launch_template" {
  defaults = { id = "lt-0123456789abcdef0", latest_version = 1 }
}

mock_resource "aws_cloudtrail" {
  defaults = { arn = "arn:aws:cloudtrail:us-east-1:111122223333:trail/mock" }
}

mock_resource "aws_iam_openid_connect_provider" {
  defaults = { arn = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com" }
}

mock_resource "aws_cloudwatch_metric_alarm" {
  defaults = { arn = "arn:aws:cloudwatch:us-east-1:111122223333:alarm:mock" }
}

mock_resource "aws_vpc" {
  defaults = { id = "vpc-0123456789abcdef0" }
}

mock_resource "aws_security_group" {
  defaults = { id = "sg-0123456789abcdef0" }
}

mock_resource "aws_vpc_endpoint" {
  defaults = { prefix_list_id = "pl-63a5400a" }
}
