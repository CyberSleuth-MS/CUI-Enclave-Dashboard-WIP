#############################################
# PrivateLink endpoints
#
# The only way out of the enclave. Service calls resolve to private
# addresses inside the endpoint subnet and travel the AWS network, never
# the public internet. With no internet gateway on the route table, a
# failed endpoint does not fall back to a public path; the request simply
# times out, which is the behavior we want.
#############################################

# Security group for the interface endpoint network interfaces.
# Accepts 443 from inside the VPC only.
resource "aws_security_group" "endpoints" {
  name        = "${local.name}-endpoints"
  description = "PrivateLink interface endpoints - HTTPS from inside the enclave only"
  vpc_id      = aws_vpc.enclave.id

  tags = {
    Name = "${local.name}-endpoints-sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_https" {
  security_group_id = aws_security_group.endpoints.id
  description       = "HTTPS from inside the enclave"
  cidr_ipv4         = var.vpc_cidr
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

# Gateway endpoint for S3. No hourly charge, no network interface.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.enclave.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.enclave.id]

  tags = {
    Name = "${local.name}-s3-endpoint"
  }
}

# Interface endpoints. KMS for decryption, and the three Systems Manager
# endpoints that make Session Manager work without any inbound port.
locals {
  interface_endpoints = var.enable_interface_endpoints ? {
    kms         = "com.amazonaws.${data.aws_region.current.name}.kms"
    ssm         = "com.amazonaws.${data.aws_region.current.name}.ssm"
    ssmmessages = "com.amazonaws.${data.aws_region.current.name}.ssmmessages"
    ec2messages = "com.amazonaws.${data.aws_region.current.name}.ec2messages"
  } : {}
}

resource "aws_vpc_endpoint" "interface" {
  for_each = local.interface_endpoints

  vpc_id              = aws_vpc.enclave.id
  service_name        = each.value
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  # Single availability zone in the lab to halve the hourly cost.
  # The production design places endpoints in both zones.
  subnet_ids         = [aws_subnet.endpoint_a.id]
  security_group_ids = [aws_security_group.endpoints.id]

  tags = {
    Name = "${local.name}-${each.key}-endpoint"
  }
}
