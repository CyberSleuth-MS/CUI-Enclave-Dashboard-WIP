variable "region" {
  description = "AWS region for the enclave. Production design targets AWS GovCloud (US); this project builds in commercial."
  type        = string
  default     = "us-east-2"
}

variable "environment" {
  description = "Environment name, used in tags and resource names."
  type        = string
  default     = "lab"
}

variable "vpc_cidr" {
  description = "CIDR block for the enclave VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "enable_interface_endpoints" {
  description = <<-EOT
    Create PrivateLink interface endpoints (KMS, SSM, SSMMessages, EC2Messages).
    These are the only meaningful hourly cost in this build, roughly $0.01/hour each
    (about $29/month if left running). The S3 gateway endpoint is always created and is free.
    Set false to build the network cheaply; set true before demonstrating private connectivity
    or using Session Manager on the fileserver.
  EOT
  type        = bool
  default     = true
}

variable "enable_fileserver" {
  description = "Create the EC2 fileserver in the CUI workload subnet. Requires enable_interface_endpoints for Session Manager access."
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "Enable GuardDuty. Free for the first 30 days per account, then usage based. Set false if a detector already exists in this account and region."
  type        = bool
  default     = true
}

variable "enable_config" {
  description = "Enable AWS Config recorder and managed rules. Rules cost fractions of a cent per evaluation."
  type        = bool
  default     = true
}

variable "log_object_lock" {
  description = <<-EOT
    Enable S3 Object Lock in GOVERNANCE mode on the log archive, making log objects immutable
    for the retention period. This is the 3.3.1 evidence-integrity control.

    IMPORTANT: leave false while iterating. Object Lock prevents object deletion, so
    `terraform destroy` may fail to empty the bucket and you will have to clean it up by hand.
    Set true for the final build and the demonstration screenshots.
  EOT
  type        = bool
  default     = false
}

variable "log_retention_days" {
  description = "Object Lock retention period in days when log_object_lock is true. Keep short in the lab."
  type        = number
  default     = 1
}

variable "enable_baseline_findings" {
  description = <<-EOT
    Create the deliberately misconfigured baseline resources that the assessment tool is
    meant to detect: a bucket with public access block disabled and no default encryption,
    a security group open to 0.0.0.0/0 on port 22, and an unencrypted EBS volume.

    These are intentional findings, not part of the enclave. Set false after the
    remediation step to demonstrate the score improvement.
  EOT
  type        = bool
  default     = true
}
