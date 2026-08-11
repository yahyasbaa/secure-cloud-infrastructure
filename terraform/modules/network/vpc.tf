# Three-tier VPC:
#   public  - load balancer only (no instance gets a public IP)
#   app     - application instances; NO route to the internet at all. AWS APIs
#             are reached through VPC endpoints, which also removes the NAT
#             gateway as a data-exfiltration path.
#   db      - RDS; route table contains only the local VPC route.

locals {
  az_count     = length(var.azs)
  public_cidrs = [for i in range(local.az_count) : cidrsubnet(var.vpc_cidr, 8, i)]
  app_cidrs    = [for i in range(local.az_count) : cidrsubnet(var.vpc_cidr, 8, 10 + i)]
  db_cidrs     = [for i in range(local.az_count) : cidrsubnet(var.vpc_cidr, 8, 20 + i)]
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true # required for private DNS on interface endpoints

  tags = { Name = "${var.name}-vpc" }
}

# Neutralise the default security group so nothing can accidentally use it.
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-default-sg-locked" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-igw" }
}

resource "aws_subnet" "public" {
  count                   = local.az_count
  vpc_id                  = aws_vpc.this.id
  cidr_block              = local.public_cidrs[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = false

  tags = { Name = "${var.name}-public-${var.azs[count.index]}", Tier = "public" }
}

resource "aws_subnet" "app" {
  count                   = local.az_count
  vpc_id                  = aws_vpc.this.id
  cidr_block              = local.app_cidrs[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = false

  tags = { Name = "${var.name}-app-${var.azs[count.index]}", Tier = "app" }
}

resource "aws_subnet" "db" {
  count                   = local.az_count
  vpc_id                  = aws_vpc.this.id
  cidr_block              = local.db_cidrs[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = false

  tags = { Name = "${var.name}-db-${var.azs[count.index]}", Tier = "db" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-public-rt" }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  count          = local.az_count
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# App tier: local route + S3 gateway endpoint route only.
resource "aws_route_table" "app" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-app-rt" }
}

resource "aws_route_table_association" "app" {
  count          = local.az_count
  subnet_id      = aws_subnet.app[count.index].id
  route_table_id = aws_route_table.app.id
}

# DB tier: local route only.
resource "aws_route_table" "db" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-db-rt" }
}

resource "aws_route_table_association" "db" {
  count          = local.az_count
  subnet_id      = aws_subnet.db[count.index].id
  route_table_id = aws_route_table.db.id
}
