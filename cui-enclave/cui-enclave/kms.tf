#############################################
# Customer managed encryption keys
#
# Two keys, deliberately separate: read access to CUI does not imply read
# access to the audit trail. Customer managed rather than AWS managed, because
# the requirement is control of the keys, not merely that encryption is on.
# Supports 3.13.11 and 3.13.16, and underpins the 22 C.F.R. 120.54 position
# that the means of decryption are not provided to a third party.
#############################################

# ---------- CUI data key ----------

data "aws_iam_policy_document" "cui_key" {
  statement {
    sid    = "EnableAccountAdministration"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${local.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  # Workload role may use the key but may not administer it.
  dynamic "statement" {
    for_each = var.enable_fileserver ? [1] : []
    content {
      sid    = "AllowWorkloadUse"
      effect = "Allow"
      principals {
        type        = "AWS"
        identifiers = [aws_iam_role.fileserver[0].arn]
      }
      actions = [
        "kms:Decrypt",
        "kms:GenerateDataKey*",
        "kms:DescribeKey",
      ]
      resources = ["*"]
    }
  }

  # EBS needs grants to attach encrypted volumes to instances.
  dynamic "statement" {
    for_each = var.enable_fileserver ? [1] : []
    content {
      sid    = "AllowAttachmentOfPersistentResources"
      effect = "Allow"
      principals {
        type        = "AWS"
        identifiers = [aws_iam_role.fileserver[0].arn]
      }
      actions   = ["kms:CreateGrant"]
      resources = ["*"]
      condition {
        test     = "Bool"
        variable = "kms:GrantIsForAWSResource"
        values   = ["true"]
      }
    }
  }
}

resource "aws_kms_key" "cui" {
  description             = "CUI data at rest - customer managed, rotation enabled"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.cui_key.json

  tags = {
    Name        = "${local.name}-cui-key"
    DataClass   = "CUI"
    Requirement = "3.13.11,3.13.16"
  }
}

resource "aws_kms_alias" "cui" {
  name          = "alias/${local.name}-cui"
  target_key_id = aws_kms_key.cui.key_id
}

# ---------- Log archive key ----------

data "aws_iam_policy_document" "logs_key" {
  statement {
    sid    = "EnableAccountAdministration"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${local.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowLogServicesToEncrypt"
    effect = "Allow"
    principals {
      type = "Service"
      identifiers = [
        "cloudtrail.amazonaws.com",
        "config.amazonaws.com",
        "delivery.logs.amazonaws.com",
      ]
    }
    actions = [
      "kms:GenerateDataKey*",
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:ReEncrypt*",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_kms_key" "logs" {
  description             = "Audit log archive - separate key so CUI access does not imply log access"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.logs_key.json

  tags = {
    Name        = "${local.name}-logs-key"
    DataClass   = "audit"
    Requirement = "3.3.1"
  }
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${local.name}-logs"
  target_key_id = aws_kms_key.logs.key_id
}
