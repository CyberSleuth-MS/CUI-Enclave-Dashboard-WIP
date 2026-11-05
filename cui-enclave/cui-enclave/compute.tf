#############################################
# Workload
#
# One fileserver in the CUI workload subnet. No public IP, no inbound
# rules at all, and no SSH key. Administrative access is through Systems
# Manager Session Manager, which gives a logged shell without opening a
# port. Supports 3.4.7 (no nonessential ports) and 3.1.12 (monitored
# remote access).
#############################################

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

# ---------- Instance role ----------

data "aws_iam_policy_document" "fileserver_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "fileserver" {
  count              = var.enable_fileserver ? 1 : 0
  name               = "${local.name}-fileserver-role"
  assume_role_policy = data.aws_iam_policy_document.fileserver_assume.json

  tags = {
    Name = "${local.name}-fileserver-role"
  }
}

# Session Manager. Note this grants no inbound network access; it is the
# agent reaching out through the VPC endpoints.
resource "aws_iam_role_policy_attachment" "fileserver_ssm" {
  count      = var.enable_fileserver ? 1 : 0
  role       = aws_iam_role.fileserver[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Least privilege access to the CUI bucket and its key. No wildcard actions,
# no access to the log archive or the log key. Supports 3.1.2.
data "aws_iam_policy_document" "fileserver_data" {
  statement {
    sid       = "ListCuiBucket"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.cui.arn]
  }

  statement {
    sid    = "ReadWriteCuiObjects"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
    ]
    resources = ["${aws_s3_bucket.cui.arn}/*"]
  }

  statement {
    sid    = "UseCuiKey"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.cui.arn]
  }
}

resource "aws_iam_role_policy" "fileserver_data" {
  count  = var.enable_fileserver ? 1 : 0
  name   = "${local.name}-fileserver-data"
  role   = aws_iam_role.fileserver[0].id
  policy = data.aws_iam_policy_document.fileserver_data.json
}

resource "aws_iam_instance_profile" "fileserver" {
  count = var.enable_fileserver ? 1 : 0
  name  = "${local.name}-fileserver-profile"
  role  = aws_iam_role.fileserver[0].name
}

# ---------- Security group ----------
#
# No ingress rules whatsoever. Egress is 443 to the endpoint security
# group only, referenced by group rather than by CIDR so access follows
# membership. The default allow-all egress rule is absent because
# Terraform only creates the rules declared here.

resource "aws_security_group" "fileserver" {
  name        = "${local.name}-fileserver"
  description = "CUI fileserver - no inbound, HTTPS egress to endpoints only"
  vpc_id      = aws_vpc.enclave.id

  tags = {
    Name        = "${local.name}-fileserver-sg"
    Requirement = "3.4.7,3.13.1"
  }
}

resource "aws_vpc_security_group_egress_rule" "fileserver_to_endpoints" {
  security_group_id            = aws_security_group.fileserver.id
  description                  = "HTTPS to PrivateLink endpoints"
  referenced_security_group_id = aws_security_group.endpoints.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

# S3 goes through the gateway endpoint, which is reached by prefix list
# rather than by security group.
data "aws_prefix_list" "s3" {
  name = "com.amazonaws.${data.aws_region.current.name}.s3"
}

resource "aws_vpc_security_group_egress_rule" "fileserver_to_s3" {
  security_group_id = aws_security_group.fileserver.id
  description       = "HTTPS to S3 via gateway endpoint"
  prefix_list_id    = data.aws_prefix_list.s3.id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

# ---------- Instance ----------

resource "aws_instance" "fileserver" {
  count = var.enable_fileserver ? 1 : 0

  ami           = data.aws_ssm_parameter.al2023.value
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.cui_workloads.id

  vpc_security_group_ids = [aws_security_group.fileserver.id]
  iam_instance_profile   = aws_iam_instance_profile.fileserver[0].name

  # No key pair. There is no SSH path to this host by design.
  associate_public_ip_address = false

  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.cui.arn
    volume_size = 8
    volume_type = "gp3"

    tags = {
      Name = "${local.name}-fileserver-root"
    }
  }

  # IMDSv2 only. Session tokens are required, which blocks the metadata
  # credential theft path used in several well known cloud breaches.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags = {
    Name        = "${local.name}-fileserver"
    Requirement = "3.13.16,3.1.12"
  }

  depends_on = [aws_vpc_endpoint.interface]
}
