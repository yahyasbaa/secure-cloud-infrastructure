# Security groups reference each other instead of CIDRs wherever possible, so
# each hop is allowed only from the exact upstream tier:
#
#   internet --443--> alb --app_port--> app --db_port--> db
#                                        \--443--> VPC endpoints / S3 prefix list
#
# db and endpoints have NO egress rules (Terraform removes AWS's default
# allow-all egress rule), so neither can initiate outbound connections.

resource "aws_security_group" "alb" {
  #checkov:skip=CKV2_AWS_5:Attached to the ALB in modules/compute through a module output; checkov does not follow cross-module references.
  name        = "${var.name}-alb"
  description = "Load balancer: HTTPS in from allowed CIDRs, app port out to app tier only"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.name}-alb" }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  #checkov:skip=CKV_AWS_260:Port 443 (not 80) is intentionally reachable from the internet on the public load balancer.
  for_each = toset(var.alb_ingress_cidrs)

  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from allowed client range"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = each.value #tfsec:ignore:aws-ec2-no-public-ingress-sgr trivy:ignore:AVD-AWS-0107 -- public HTTPS entry point by design, protected by WAF
}

resource "aws_vpc_security_group_egress_rule" "alb_to_app" {
  security_group_id            = aws_security_group.alb.id
  description                  = "Forward to application targets"
  ip_protocol                  = "tcp"
  from_port                    = var.app_port
  to_port                      = var.app_port
  referenced_security_group_id = aws_security_group.app.id
}

resource "aws_security_group" "app" {
  #checkov:skip=CKV2_AWS_5:Attached to the launch template in modules/compute through a module output; checkov does not follow cross-module references.
  name        = "${var.name}-app"
  description = "Application: app port from ALB only; out to DB, VPC endpoints and S3 only"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.name}-app" }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "app_from_alb" {
  security_group_id            = aws_security_group.app.id
  description                  = "Application traffic from the load balancer"
  ip_protocol                  = "tcp"
  from_port                    = var.app_port
  to_port                      = var.app_port
  referenced_security_group_id = aws_security_group.alb.id
}

resource "aws_vpc_security_group_egress_rule" "app_to_db" {
  security_group_id            = aws_security_group.app.id
  description                  = "PostgreSQL to the database tier"
  ip_protocol                  = "tcp"
  from_port                    = var.db_port
  to_port                      = var.db_port
  referenced_security_group_id = aws_security_group.db.id
}

resource "aws_vpc_security_group_egress_rule" "app_to_endpoints" {
  security_group_id            = aws_security_group.app.id
  description                  = "HTTPS to interface VPC endpoints (AWS APIs)"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.endpoints.id
}

resource "aws_vpc_security_group_egress_rule" "app_to_s3" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS to S3 through the gateway endpoint (OS packages, image layers)"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  prefix_list_id    = aws_vpc_endpoint.s3.prefix_list_id
}

resource "aws_security_group" "db" {
  #checkov:skip=CKV2_AWS_5:Attached to the RDS instance in modules/database through a module output; checkov does not follow cross-module references.
  name        = "${var.name}-db"
  description = "Database: PostgreSQL from app tier only; no egress"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.name}-db" }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "db_from_app" {
  security_group_id            = aws_security_group.db.id
  description                  = "PostgreSQL from application tier"
  ip_protocol                  = "tcp"
  from_port                    = var.db_port
  to_port                      = var.db_port
  referenced_security_group_id = aws_security_group.app.id
}

resource "aws_security_group" "endpoints" {
  name        = "${var.name}-endpoints"
  description = "Interface VPC endpoints: HTTPS from app tier only; no egress"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.name}-endpoints" }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_from_app" {
  security_group_id            = aws_security_group.endpoints.id
  description                  = "HTTPS from application tier"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.app.id
}
