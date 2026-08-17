output "alb_dns_name" {
  description = "Public DNS name of the load balancer."
  value       = aws_lb.this.dns_name
}

output "alb_arn" {
  description = "Load balancer ARN."
  value       = aws_lb.this.arn
}

output "alb_arn_suffix" {
  description = "ALB ARN suffix (CloudWatch dimension)."
  value       = aws_lb.this.arn_suffix
}

output "target_group_arn_suffix" {
  description = "Target group ARN suffix (CloudWatch dimension)."
  value       = aws_lb_target_group.app.arn_suffix
}

output "ecr_repository_url" {
  description = "ECR repository URL."
  value       = aws_ecr_repository.app.repository_url
}

output "asg_arn" {
  description = "Auto Scaling group ARN."
  value       = aws_autoscaling_group.app.arn
}

output "asg_name" {
  description = "Auto Scaling group name."
  value       = aws_autoscaling_group.app.name
}

output "waf_web_acl_name" {
  description = "WAF web ACL name (null when WAF is disabled)."
  value       = var.enable_waf ? aws_wafv2_web_acl.this[0].name : null
}

output "image_tag_parameter_name" {
  description = "SSM parameter that selects the deployed image tag."
  value       = aws_ssm_parameter.image_tag.name
}
