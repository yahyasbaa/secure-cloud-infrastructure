# Network ACLs are a stateless second layer under the security groups. They
# bound what each tier can talk to even if a security group is later
# misconfigured. Ephemeral port ranges are needed for return traffic.
# Every NACL ends with AWS's immutable "*" DENY rule, so anything not
# explicitly allowed below (e.g. internet -> db) is dropped.

locals {
  ephemeral_from = 1024
  # Linux clients (app instances) use 32768-60999; S3 return traffic only
  # needs this range, which also avoids opening admin ports such as 3389.
  linux_ephemeral_from = 32768
  ephemeral_to         = 65535
}

#----------------------------------------------------------------- public tier
resource "aws_network_acl" "public" {
  vpc_id     = aws_vpc.this.id
  subnet_ids = aws_subnet.public[*].id
  tags       = { Name = "${var.name}-public-nacl" }
}

resource "aws_network_acl_rule" "public_in_https" {
  count          = length(var.alb_ingress_cidrs)
  network_acl_id = aws_network_acl.public.id
  rule_number    = 100 + count.index
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = var.alb_ingress_cidrs[count.index] #tfsec:ignore:aws-ec2-no-public-ingress-acl trivy:ignore:AVD-AWS-0105 -- HTTPS entry point for the public ALB
  from_port      = 443
  to_port        = 443
}

resource "aws_network_acl_rule" "public_in_return_from_app" {
  count          = local.az_count
  network_acl_id = aws_network_acl.public.id
  rule_number    = 200 + count.index
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = local.app_cidrs[count.index]
  from_port      = local.ephemeral_from
  to_port        = local.ephemeral_to
}

resource "aws_network_acl_rule" "public_out_return_to_clients" {
  count          = length(var.alb_ingress_cidrs)
  network_acl_id = aws_network_acl.public.id
  rule_number    = 100 + count.index
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = var.alb_ingress_cidrs[count.index]
  from_port      = local.ephemeral_from
  to_port        = local.ephemeral_to
}

resource "aws_network_acl_rule" "public_out_to_app" {
  count          = local.az_count
  network_acl_id = aws_network_acl.public.id
  rule_number    = 200 + count.index
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = local.app_cidrs[count.index]
  from_port      = var.app_port
  to_port        = var.app_port
}

#-------------------------------------------------------------------- app tier
resource "aws_network_acl" "app" {
  vpc_id     = aws_vpc.this.id
  subnet_ids = aws_subnet.app[*].id
  tags       = { Name = "${var.name}-app-nacl" }
}

resource "aws_network_acl_rule" "app_in_from_alb" {
  count          = local.az_count
  network_acl_id = aws_network_acl.app.id
  rule_number    = 100 + count.index
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = local.public_cidrs[count.index]
  from_port      = var.app_port
  to_port        = var.app_port
}

resource "aws_network_acl_rule" "app_in_endpoints" {
  count          = local.az_count
  network_acl_id = aws_network_acl.app.id
  rule_number    = 200 + count.index
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = local.app_cidrs[count.index]
  from_port      = 443
  to_port        = 443
}

resource "aws_network_acl_rule" "app_in_return_vpc" {
  network_acl_id = aws_network_acl.app.id
  rule_number    = 300
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = var.vpc_cidr
  from_port      = local.ephemeral_from
  to_port        = local.ephemeral_to
}

# Return traffic from S3 (public IP space reached via the gateway endpoint).
# App subnets have no internet route, so nothing on the internet can use this
# rule to initiate a connection.
resource "aws_network_acl_rule" "app_in_return_s3" {
  network_acl_id = aws_network_acl.app.id
  rule_number    = 400
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0" #tfsec:ignore:aws-ec2-no-public-ingress-acl trivy:ignore:AVD-AWS-0105 -- S3 gateway-endpoint return traffic; subnet has no internet route
  from_port      = local.linux_ephemeral_from
  to_port        = local.ephemeral_to
}

resource "aws_network_acl_rule" "app_out_https" {
  network_acl_id = aws_network_acl.app.id
  rule_number    = 100
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0" # bounded by the route table: only VPC-local and S3 prefix-list routes exist
  from_port      = 443
  to_port        = 443
}

resource "aws_network_acl_rule" "app_out_db" {
  count          = local.az_count
  network_acl_id = aws_network_acl.app.id
  rule_number    = 200 + count.index
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = local.db_cidrs[count.index]
  from_port      = var.db_port
  to_port        = var.db_port
}

resource "aws_network_acl_rule" "app_out_return_vpc" {
  network_acl_id = aws_network_acl.app.id
  rule_number    = 300
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = var.vpc_cidr
  from_port      = local.ephemeral_from
  to_port        = local.ephemeral_to
}

#--------------------------------------------------------------------- db tier
resource "aws_network_acl" "db" {
  vpc_id     = aws_vpc.this.id
  subnet_ids = aws_subnet.db[*].id
  tags       = { Name = "${var.name}-db-nacl" }
}

resource "aws_network_acl_rule" "db_in_from_app" {
  count          = local.az_count
  network_acl_id = aws_network_acl.db.id
  rule_number    = 100 + count.index
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = local.app_cidrs[count.index]
  from_port      = var.db_port
  to_port        = var.db_port
}

resource "aws_network_acl_rule" "db_out_return_to_app" {
  count          = local.az_count
  network_acl_id = aws_network_acl.db.id
  rule_number    = 100 + count.index
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = local.app_cidrs[count.index]
  from_port      = local.ephemeral_from
  to_port        = local.ephemeral_to
}
