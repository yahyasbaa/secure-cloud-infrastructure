output "app_role_name" {
  description = "Application role name."
  value       = aws_iam_role.app.name
}

output "app_role_arn" {
  description = "Application role ARN."
  value       = aws_iam_role.app.arn
}

output "app_instance_profile_arn" {
  description = "Application instance profile ARN."
  value       = aws_iam_instance_profile.app.arn
}

output "deployment_role_arn" {
  description = "Role GitHub Actions assumes via OIDC (set as AWS_DEPLOY_ROLE_ARN in the GitHub environment)."
  value       = aws_iam_role.deployment.arn
}

output "monitoring_role_arn" {
  description = "Read-only observability role for on-call engineers."
  value       = aws_iam_role.monitoring.arn
}

output "security_audit_role_arn" {
  description = "Read-only security audit role."
  value       = aws_iam_role.security_audit.arn
}
