#############################################
# Deliberate baseline findings
#
# These resources are NOT part of the enclave. They represent the
# contractor's unassessed environment before remediation: the kind of
# configuration a small shop ends up with when nobody has been measuring.
#
# They exist so the assessment tool has real findings to detect and so the
# before-and-after score change is genuine rather than staged.
#
# Set enable_baseline_findings = false and re-apply to perform the
# remediation step of the demonstration.
#############################################

# Finding 1 (3.1.22): bucket with public access block disabled and no
# customer managed encryption. Account-level public access settings still
# protect the data, so nothing is actually exposed, but the bucket-level
# control an assessor looks for is off.
resource "aws_s3_bucket" "baseline_drawings" {
  count         = var.enable_baseline_findings ? 1 : 0
  bucket        = "${local.name}-baseline-drawings-${local.account_id}"
  force_destroy = true

  tags = {
    Name    = "baseline-finding"
    Finding = "3.1.22 public access block disabled, 3.13.16 no customer managed key"
    Scope   = "pre-remediation-baseline"
  }
}

resource "aws_s3_bucket_public_access_block" "baseline_drawings" {
  count                   = var.enable_baseline_findings ? 1 : 0
  bucket                  = aws_s3_bucket.baseline_drawings[0].id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Finding 2 (3.4.7): security group permitting SSH from anywhere.
# This is the single most common real world finding, and the one the
# live demonstration closes.
resource "aws_security_group" "baseline_legacy" {
  count       = var.enable_baseline_findings ? 1 : 0
  name        = "${local.name}-baseline-legacy"
  description = "Deliberate baseline finding - SSH open to the internet"
  vpc_id      = aws_vpc.enclave.id

  tags = {
    Name    = "baseline-finding"
    Finding = "3.4.7 SSH open to 0.0.0.0/0"
    Scope   = "pre-remediation-baseline"
  }
}

resource "aws_vpc_security_group_ingress_rule" "baseline_ssh_open" {
  count             = var.enable_baseline_findings ? 1 : 0
  security_group_id = aws_security_group.baseline_legacy[0].id
  description       = "Deliberate finding: SSH from anywhere"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "baseline_rdp_open" {
  count             = var.enable_baseline_findings ? 1 : 0
  security_group_id = aws_security_group.baseline_legacy[0].id
  description       = "Deliberate finding: RDP from anywhere"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 3389
  to_port           = 3389
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "baseline_all_out" {
  count             = var.enable_baseline_findings ? 1 : 0
  security_group_id = aws_security_group.baseline_legacy[0].id
  description       = "Deliberate finding: unrestricted egress"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# Finding 3 (3.13.16): unencrypted volume.
resource "aws_ebs_volume" "baseline_unencrypted" {
  count             = var.enable_baseline_findings ? 1 : 0
  availability_zone = local.az_a
  size              = 1
  type              = "gp3"
  encrypted         = false

  tags = {
    Name    = "baseline-finding"
    Finding = "3.13.16 unencrypted volume"
    Scope   = "pre-remediation-baseline"
  }
}
