output "vpc_id" {
  description = "VPC ID."
  value       = aws_vpc.this.id
}

output "vpc_cidr" {
  description = "VPC CIDR block."
  value       = aws_vpc.this.cidr_block
}

output "public_subnet_ids" {
  description = "Public subnet IDs (load balancer)."
  value       = aws_subnet.public[*].id
}

output "app_subnet_ids" {
  description = "Private application subnet IDs."
  value       = aws_subnet.app[*].id
}

output "db_subnet_ids" {
  description = "Private database subnet IDs."
  value       = aws_subnet.db[*].id
}

output "alb_security_group_id" {
  description = "Load balancer security group."
  value       = aws_security_group.alb.id
}

output "app_security_group_id" {
  description = "Application security group."
  value       = aws_security_group.app.id
}

output "db_security_group_id" {
  description = "Database security group."
  value       = aws_security_group.db.id
}

output "endpoints_security_group_id" {
  description = "Interface endpoint security group."
  value       = aws_security_group.endpoints.id
}

output "interface_endpoint_ids" {
  description = "Interface endpoint IDs keyed by service."
  value       = { for k, v in aws_vpc_endpoint.interface : k => v.id }
}

output "flow_logs_role_arn" {
  description = "Role used by VPC Flow Logs."
  value       = aws_iam_role.flow_logs.arn
}
