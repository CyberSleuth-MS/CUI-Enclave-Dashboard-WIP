#############################################
# Audit, configuration recording, and detection
#
# CloudTrail records what was called, Config records what things look like,
# flow logs record what moved on the network, and GuardDuty looks at all of
# it for threats. Everything lands in the archive.
# Supports 3.3.1, 3.3.2, 3.4.1, 3.4.2, and 3.14.6.
#############################################

# ---------- CloudTrail ----------

resource "aws_cloudtrail" "enclave" {
  name           = "${local.name}-trail"
  s3_bucket_name = aws_s3_bucket.log_archive.id

  # All regions, so activity outside the enclave's region is still captured.
  is_multi_region_trail = true

  # Log file validation produces a digest file that proves the log has not
  # been altered. This is the difference between a log and evidence.
  enable_log_file_validation = true

  # Encrypt the trail with the log key, not the CUI key.
  kms_key_id = aws_kms_key.logs.arn

  # Data events on the CUI bucket: object-level reads and writes, not just
  # management calls. Scoped to the one bucket to keep the cost near zero.
  advanced_event_selector {
    name = "CUI bucket object activity"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }

    field_selector {
      field       = "resources.ARN"
      starts_with = ["${aws_s3_bucket.cui.arn}/"]
    }
  }

  advanced_event_selector {
    name = "Management events"

    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  tags = {
    Name        = "${local.name}-trail"
    Requirement = "3.3.1,3.3.2"
  }

  depends_on = [
    aws_s3_bucket_policy.log_archive,
    aws_kms_key.logs,
  ]
}

# ---------- AWS Config ----------

data "aws_iam_policy_document" "config_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "config" {
  count              = var.enable_config ? 1 : 0
  name               = "${local.name}-config-role"
  assume_role_policy = data.aws_iam_policy_document.config_assume.json
}

resource "aws_iam_role_policy_attachment" "config_managed" {
  count      = var.enable_config ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
}

# Config needs to write to the archive and use the log key.
data "aws_iam_policy_document" "config_delivery" {
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.log_archive.arn, "${aws_s3_bucket.log_archive.arn}/*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"]
    resources = [aws_kms_key.logs.arn]
  }
}

resource "aws_iam_role_policy" "config_delivery" {
  count  = var.enable_config ? 1 : 0
  name   = "${local.name}-config-delivery"
  role   = aws_iam_role.config[0].id
  policy = data.aws_iam_policy_document.config_delivery.json
}

resource "aws_config_configuration_recorder" "enclave" {
  count    = var.enable_config ? 1 : 0
  name     = "${local.name}-recorder"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "enclave" {
  count          = var.enable_config ? 1 : 0
  name           = "${local.name}-delivery"
  s3_bucket_name = aws_s3_bucket.log_archive.id
  s3_key_prefix  = "config"

  depends_on = [
    aws_config_configuration_recorder.enclave,
    aws_s3_bucket_policy.log_archive,
  ]
}

resource "aws_config_configuration_recorder_status" "enclave" {
  count      = var.enable_config ? 1 : 0
  name       = aws_config_configuration_recorder.enclave[0].name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.enclave]
}

# Managed rules, each chosen because it maps to one of the selected
# requirements. These evaluate continuously; the Python tool evaluates on
# demand and scores. Both are useful, and they cross-check each other.
locals {
  config_rules = var.enable_config ? {
    "iam-user-mfa-enabled" = {
      source_identifier = "IAM_USER_MFA_ENABLED"
      requirement       = "3.5.3"
    }
    "s3-bucket-public-read-prohibited" = {
      source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
      requirement       = "3.1.22"
    }
    "s3-bucket-server-side-encryption-enabled" = {
      source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
      requirement       = "3.13.16"
    }
    "encrypted-volumes" = {
      source_identifier = "ENCRYPTED_VOLUMES"
      requirement       = "3.13.16"
    }
    "restricted-ssh" = {
      source_identifier = "INCOMING_SSH_DISABLED"
      requirement       = "3.4.7"
    }
    "cloud-trail-log-file-validation-enabled" = {
      source_identifier = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
      requirement       = "3.3.1"
    }
  } : {}
}

resource "aws_config_config_rule" "managed" {
  for_each = local.config_rules

  name        = "${local.name}-${each.key}"
  description = "NIST SP 800-171 ${each.value.requirement}"

  source {
    owner             = "AWS"
    source_identifier = each.value.source_identifier
  }

  tags = {
    Requirement = each.value.requirement
  }

  depends_on = [aws_config_configuration_recorder_status.enclave]
}

# ---------- GuardDuty ----------

resource "aws_guardduty_detector" "enclave" {
  count                        = var.enable_guardduty ? 1 : 0
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = {
    Name        = "${local.name}-guardduty"
    Requirement = "3.14.6"
  }
}
