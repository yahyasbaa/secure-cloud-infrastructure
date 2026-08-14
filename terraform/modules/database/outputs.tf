output "identifier" {
  description = "RDS instance identifier."
  value       = aws_db_instance.this.identifier
}

output "instance_arn" {
  description = "RDS instance ARN."
  value       = aws_db_instance.this.arn
}

output "monitoring_role_arn" {
  description = "Enhanced monitoring role ARN."
  value       = aws_iam_role.rds_monitoring.arn
}

output "address" {
  description = "Private DNS name of the database."
  value       = aws_db_instance.this.address
}

output "db_name" {
  description = "Initial database name."
  value       = aws_db_instance.this.db_name
}

output "master_secret_arn" {
  description = "ARN of the RDS-managed master credential secret."
  value       = aws_db_instance.this.master_user_secret[0].secret_arn
}

output "postgresql_log_group_name" {
  description = "Exported PostgreSQL log group."
  value       = aws_cloudwatch_log_group.postgresql.name
}

output "log_group_arns" {
  description = "Database log group ARNs."
  value       = [aws_cloudwatch_log_group.postgresql.arn, aws_cloudwatch_log_group.upgrade.arn]
}
