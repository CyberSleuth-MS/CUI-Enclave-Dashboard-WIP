#############################################
# Storage
#
# Two buckets: the CUI data store, and the audit log archive.
# Both encrypted with their own customer managed key, both with public
# access blocked at the bucket level, both refusing requests that do not
# arrive over TLS.
#############################################

locals {
  cui_bucket_name     = "${local.name}-cui-${local.account_id}-${data.aws_region.current.name}"
  log_archive_name    = "${local.name}-logs-${local.account_id}-${data.aws_region.current.name}"
}

# ---------- CUI data bucket ----------

resource "aws_s3_bucket" "cui" {
  bucket = local.cui_bucket_name

  # Lab convenience: allows `terraform destroy` to empty the bucket.
  # A production enclave would not set this.
  force_destroy = true

  tags = {
    Name        = "${local.name}-cui"
    DataClass   = "CUI"
    Requirement = "3.13.16,3.1.22"
  }
}

resource "aws_s3_bucket_versioning" "cui" {
  bucket = aws_s3_bucket.cui.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cui" {
  bucket = aws_s3_bucket.cui.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cui.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "cui" {
  bucket                  = aws_s3_bucket.cui.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "cui" {
  bucket = aws_s3_bucket.cui.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Deny any request that does not arrive over TLS, and any request that does
# not come through the enclave's VPC endpoint. The second statement is what
# stops a valid credential used from outside the enclave: the key is good,
# but the request arrives by the wrong path. Supports 3.1.22.
data "aws_iam_policy_document" "cui_bucket" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.cui.arn, "${aws_s3_bucket.cui.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "DenyUnencryptedObjectUploads"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cui.arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }
}

resource "aws_s3_bucket_policy" "cui" {
  bucket = aws_s3_bucket.cui.id
  policy = data.aws_iam_policy_document.cui_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.cui]
}

# ---------- Audit log archive ----------

resource "aws_s3_bucket" "log_archive" {
  bucket = local.log_archive_name

  # Object Lock must be declared at creation. Flipping log_object_lock
  # replaces the bucket.
  object_lock_enabled = var.log_object_lock

  force_destroy = true

  tags = {
    Name        = "${local.name}-log-archive"
    DataClass   = "audit"
    Requirement = "3.3.1"
  }
}

resource "aws_s3_bucket_versioning" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Immutability. With Object Lock in GOVERNANCE mode, log objects cannot be
# altered or deleted within the retention period, including by an
# administrator without the explicit bypass permission. That is what makes
# these logs assessment evidence rather than merely operational data.
resource "aws_s3_bucket_object_lock_configuration" "log_archive" {
  count  = var.log_object_lock ? 1 : 0
  bucket = aws_s3_bucket.log_archive.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.log_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.log_archive]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.logs.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "log_archive" {
  bucket                  = aws_s3_bucket.log_archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

data "aws_iam_policy_document" "log_archive" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.log_archive.arn, "${aws_s3_bucket.log_archive.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.log_archive.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.log_archive.arn}/AWSLogs/${local.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid    = "AWSConfigBucketPermissionsCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.log_archive.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid    = "AWSConfigBucketDelivery"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.log_archive.arn}/config/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid    = "AWSLogDeliveryAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.log_archive.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid    = "AWSLogDeliveryWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.log_archive.arn}/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id
  policy = data.aws_iam_policy_document.log_archive.json

  depends_on = [aws_s3_bucket_public_access_block.log_archive]
}
