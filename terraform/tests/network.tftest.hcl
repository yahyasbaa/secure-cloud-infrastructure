# Network isolation guarantees, asserted on the network module in isolation.

mock_provider "aws" {
  source = "./tests/mocks"
}

variables {
  name                        = "sci-test"
  account_id                  = "111122223333"
  partition                   = "aws"
  region                      = "us-east-1"
  flow_log_group_arn          = "arn:aws:logs:us-east-1:111122223333:log-group:/sci-test/vpc-flow-logs"
  vpc_cidr                    = "10.20.0.0/16"
  azs                         = ["us-east-1a", "us-east-1b"]
  interface_endpoint_az_count = 1
  alb_ingress_cidrs           = ["0.0.0.0/0"]
  app_port                    = 8443
  db_port                     = 5432
}

run "network" {
  command = apply

  module {
    source = "./modules/network"
  }

  assert {
    condition     = alltrue([for s in concat(aws_subnet.public, aws_subnet.app, aws_subnet.db) : s.map_public_ip_on_launch == false])
    error_message = "no subnet may auto-assign public IPs"
  }

  assert {
    condition     = length(aws_subnet.app) == 2 && length(aws_subnet.db) == 2 && length(aws_subnet.public) == 2
    error_message = "each tier must span two availability zones"
  }

  # Only the public route table has an internet route; app and db have none.
  assert {
    condition     = aws_route.public_internet.route_table_id == aws_route_table.public.id && aws_route.public_internet.destination_cidr_block == "0.0.0.0/0"
    error_message = "internet route must be attached to the public route table only"
  }

  assert {
    condition     = length(aws_route_table.app.route) == 0 && length(aws_route_table.db.route) == 0
    error_message = "private route tables must not declare inline routes (no internet/NAT path)"
  }

  # Internet -> ALB: HTTPS only.
  assert {
    condition     = alltrue([for r in aws_vpc_security_group_ingress_rule.alb_https : r.from_port == 443 && r.to_port == 443 && r.ip_protocol == "tcp"])
    error_message = "ALB may only accept 443/tcp"
  }

  # ALB -> app: application port only, referenced by security group.
  assert {
    condition     = aws_vpc_security_group_ingress_rule.app_from_alb.from_port == 8443 && aws_vpc_security_group_ingress_rule.app_from_alb.referenced_security_group_id == aws_security_group.alb.id && aws_vpc_security_group_ingress_rule.app_from_alb.cidr_ipv4 == null
    error_message = "app tier must accept only the app port from the ALB security group"
  }

  # App -> DB: database port only, referenced by security group.
  assert {
    condition     = aws_vpc_security_group_ingress_rule.db_from_app.from_port == 5432 && aws_vpc_security_group_ingress_rule.db_from_app.to_port == 5432 && aws_vpc_security_group_ingress_rule.db_from_app.referenced_security_group_id == aws_security_group.app.id && aws_vpc_security_group_ingress_rule.db_from_app.cidr_ipv4 == null
    error_message = "database must accept only 5432 from the app security group"
  }

  # Internet -> DB: the DB NACL admits only the app subnets on 5432.
  assert {
    condition     = alltrue([for r in aws_network_acl_rule.db_in_from_app : r.from_port == 5432 && r.to_port == 5432 && contains(["10.20.10.0/24", "10.20.11.0/24"], r.cidr_block)])
    error_message = "DB NACL must only admit app subnets on 5432"
  }

  assert {
    condition     = alltrue([for r in aws_network_acl_rule.db_out_return_to_app : contains(["10.20.10.0/24", "10.20.11.0/24"], r.cidr_block)])
    error_message = "DB NACL egress must only return traffic to app subnets"
  }

  # App -> outside: only the DB, endpoints and the S3 prefix list.
  assert {
    condition     = aws_vpc_security_group_egress_rule.app_to_s3.prefix_list_id != null && aws_vpc_security_group_egress_rule.app_to_s3.cidr_ipv4 == null
    error_message = "app egress to S3 must use the gateway endpoint prefix list, not a CIDR"
  }

  assert {
    condition     = aws_vpc_endpoint.s3.vpc_endpoint_type == "Gateway" && contains(aws_vpc_endpoint.s3.route_table_ids, aws_route_table.app.id)
    error_message = "S3 gateway endpoint must serve the app route table"
  }

  assert {
    condition     = alltrue([for e in aws_vpc_endpoint.interface : e.private_dns_enabled && length(e.subnet_ids) == 1])
    error_message = "interface endpoints must use private DNS and the configured AZ count"
  }

  assert {
    condition     = aws_flow_log.vpc.traffic_type == "ALL" && aws_flow_log.vpc.max_aggregation_interval == 60
    error_message = "VPC flow logs must capture ALL traffic at 1-minute aggregation"
  }

  assert {
    condition     = length(aws_default_security_group.this.ingress) == 0 && length(aws_default_security_group.this.egress) == 0
    error_message = "default security group must have no rules"
  }
}

run "restricted_alb_ingress" {
  command = plan

  module {
    source = "./modules/network"
  }

  variables {
    alb_ingress_cidrs = ["203.0.113.0/24", "198.51.100.0/24"]
  }

  assert {
    condition     = toset([for r in aws_vpc_security_group_ingress_rule.alb_https : r.cidr_ipv4]) == toset(["203.0.113.0/24", "198.51.100.0/24"])
    error_message = "ALB ingress must follow alb_ingress_cidrs exactly"
  }

  assert {
    condition     = toset([for r in aws_network_acl_rule.public_in_https : r.cidr_block]) == toset(["203.0.113.0/24", "198.51.100.0/24"])
    error_message = "public NACL must follow alb_ingress_cidrs exactly"
  }
}
