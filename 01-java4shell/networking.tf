# ================================================================================
# Networking
# Two-tier network. The public subnets exist only to host the NAT gateway; the
# three lab nodes live in the private subnets with no public IP and no inbound
# path from the internet. Outbound (Corretto downloads, apt, SSM endpoints)
# goes through the NAT gateway. The only way to reach a node is SSM Session
# Manager — there is no ALB and no open ingress anywhere in this stack.
#
# CIDR layout — 10.0.0.0/24 split into four /26 blocks (64 addresses each):
#   10.0.0.0/26   — public  us-east-2a  (NAT gateway)
#   10.0.0.64/26  — public  us-east-2b  (spare / AZ symmetry)
#   10.0.0.128/26 — private us-east-2a  (vuln-jdk21, vuln-jdk17, vuln-jdk25, safe-intel)
#   10.0.0.192/26 — private us-east-2b  (safe-arm)
# ================================================================================

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/24"

  # DNS support and hostnames are required for SSM Session Manager to function
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${local.name}-vpc" }
}

# The IGW is the VPC's on-ramp to the internet. Only the NAT gateway in the
# public subnet uses it; the private nodes never touch it directly.
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${local.name}-igw" }
}

# ================================================================================
# Public Subnets
# Two AZs for symmetry with the private tier. Only the NAT gateway sits here.
# ================================================================================

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.0.0/26"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true

  tags = { Name = "${local.name}-public-${var.region}a" }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.0.64/26"
  availability_zone       = "${var.region}b"
  map_public_ip_on_launch = true

  tags = { Name = "${local.name}-public-${var.region}b" }
}

# All internet-bound traffic from public subnets exits through the IGW
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${local.name}-public-rt" }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

# ================================================================================
# NAT Gateway
# Sits in a public subnet with internet access via the IGW. The private nodes
# route outbound traffic here to download Corretto and reach the SSM endpoints.
# Inbound connections cannot be initiated through a NAT gateway — it is
# egress-only, which is exactly what an intentionally-vulnerable lab wants.
# ================================================================================

resource "aws_eip" "nat" {
  domain = "vpc"

  tags = { Name = "${local.name}-nat-eip" }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_a.id

  tags = { Name = "${local.name}-nat" }

  # The IGW must exist before the NAT gateway can forward to the internet
  depends_on = [aws_internet_gateway.main]
}

# ================================================================================
# Private Subnets
# The three lab nodes live here. No public IPs; all egress via the NAT gateway.
# Unreachable from the internet by design.
# ================================================================================

resource "aws_subnet" "private_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.0.128/26"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = false

  tags = { Name = "${local.name}-private-${var.region}a" }
}

resource "aws_subnet" "private_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.0.192/26"
  availability_zone       = "${var.region}b"
  map_public_ip_on_launch = false

  tags = { Name = "${local.name}-private-${var.region}b" }
}

# All internet-bound traffic from private subnets exits through the NAT gateway
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = { Name = "${local.name}-private-rt" }
}

resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private.id
}
