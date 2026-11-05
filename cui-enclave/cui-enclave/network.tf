#############################################
# Enclave network
#
# Four subnet tiers, no internet gateway anywhere in this file.
# The absence of an IGW is a deliberate control, not an omission:
# there is no network path out of the enclave to the public internet.
# Supports 3.13.1 (boundary protection) and 3.13.5 (subnet separation).
#############################################

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  az_a       = data.aws_availability_zones.available.names[0]
  az_b       = data.aws_availability_zones.available.names[1]
  name       = "cui-enclave"
}

resource "aws_vpc" "enclave" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true # required for private DNS on interface endpoints

  tags = {
    Name = local.name
  }
}

#############################################
# Subnets
#############################################

# Access tier: terminates remote access only. In the production design this
# holds the Client VPN endpoint. Isolated so the one component that accepts
# connections from outside holds no data.
resource "aws_subnet" "access" {
  vpc_id            = aws_vpc.enclave.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = local.az_a

  tags = {
    Name = "${local.name}-access"
    Tier = "access"
  }
}

# Endpoint tier: holds the PrivateLink network interfaces. Separate so the
# CUI subnets can be locked down without cutting off AWS service access.
resource "aws_subnet" "endpoint_a" {
  vpc_id            = aws_vpc.enclave.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = local.az_a

  tags = {
    Name = "${local.name}-endpoint-a"
    Tier = "endpoint"
  }
}

resource "aws_subnet" "endpoint_b" {
  vpc_id            = aws_vpc.enclave.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = local.az_b

  tags = {
    Name = "${local.name}-endpoint-b"
    Tier = "endpoint"
  }
}

# CUI workload tier: file services.
resource "aws_subnet" "cui_workloads" {
  vpc_id            = aws_vpc.enclave.id
  cidr_block        = "10.0.10.0/24"
  availability_zone = local.az_a

  tags = {
    Name = "${local.name}-cui-workloads"
    Tier = "cui"
  }
}

# CUI desktop tier: virtual desktops in the production design.
resource "aws_subnet" "cui_desktops" {
  vpc_id            = aws_vpc.enclave.id
  cidr_block        = "10.0.11.0/24"
  availability_zone = local.az_b

  tags = {
    Name = "${local.name}-cui-desktops"
    Tier = "cui"
  }
}

#############################################
# Routing
#
# One route table, carrying only the local route. No 0.0.0.0/0 entry exists,
# which is what makes the enclave unable to reach the internet.
#############################################

resource "aws_route_table" "enclave" {
  vpc_id = aws_vpc.enclave.id

  tags = {
    Name = "${local.name}-rt"
    Note = "No 0.0.0.0/0 route: enclave has no internet path"
  }
}

resource "aws_route_table_association" "access" {
  subnet_id      = aws_subnet.access.id
  route_table_id = aws_route_table.enclave.id
}

resource "aws_route_table_association" "endpoint_a" {
  subnet_id      = aws_subnet.endpoint_a.id
  route_table_id = aws_route_table.enclave.id
}

resource "aws_route_table_association" "endpoint_b" {
  subnet_id      = aws_subnet.endpoint_b.id
  route_table_id = aws_route_table.enclave.id
}

resource "aws_route_table_association" "cui_workloads" {
  subnet_id      = aws_subnet.cui_workloads.id
  route_table_id = aws_route_table.enclave.id
}

resource "aws_route_table_association" "cui_desktops" {
  subnet_id      = aws_subnet.cui_desktops.id
  route_table_id = aws_route_table.enclave.id
}

#############################################
# Network ACLs
#
# Stateless filtering at the subnet boundary. Return traffic needs its own
# rule, which is the usual source of confusion when both NACLs and security
# groups are in play.
#############################################

resource "aws_network_acl" "cui" {
  vpc_id     = aws_vpc.enclave.id
  subnet_ids = [aws_subnet.cui_workloads.id, aws_subnet.cui_desktops.id]

  # Inbound: only from inside the VPC.
  ingress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 0
    to_port    = 0
  }

  # Outbound: only to inside the VPC.
  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name = "${local.name}-cui-nacl"
  }
}

#############################################
# VPC Flow Logs
#
# Every connection inside the enclave, accepted or rejected, written to the
# immutable archive. Supports 3.14.6 and provides the REJECT evidence used
# to demonstrate that a closed port is actually closed.
#############################################

resource "aws_flow_log" "enclave" {
  log_destination      = aws_s3_bucket.log_archive.arn
  log_destination_type = "s3"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.enclave.id

  tags = {
    Name = "${local.name}-flow-logs"
  }

  depends_on = [aws_s3_bucket_policy.log_archive]
}
