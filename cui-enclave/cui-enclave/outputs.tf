output "vpc_id" {
  description = "Enclave VPC id"
  value       = aws_vpc.enclave.id
}

output "vpc_cidr" {
  description = "Enclave VPC CIDR"
  value       = aws_vpc.enclave.cidr_block
}

output "subnets" {
  description = "Subnet tiers and their CIDR ranges"
  value = {
    access        = "${aws_subnet.access.id} (${aws_subnet.access.cidr_block}, ${aws_subnet.access.availability_zone})"
    endpoint_a    = "${aws_subnet.endpoint_a.id} (${aws_subnet.endpoint_a.cidr_block}, ${aws_subnet.endpoint_a.availability_zone})"
    endpoint_b    = "${aws_subnet.endpoint_b.id} (${aws_subnet.endpoint_b.cidr_block}, ${aws_subnet.endpoint_b.availability_zone})"
    cui_workloads = "${aws_subnet.cui_workloads.id} (${aws_subnet.cui_workloads.cidr_block}, ${aws_subnet.cui_workloads.availability_zone})"
    cui_desktops  = "${aws_subnet.cui_desktops.id} (${aws_subnet.cui_desktops.cidr_block}, ${aws_subnet.cui_desktops.availability_zone})"
  }
}

output "internet_gateway_count" {
  description = "Deliberately zero. The enclave has no path to the public internet."
  value       = 0
}

output "cui_bucket" {
  description = "CUI data bucket"
  value       = aws_s3_bucket.cui.id
}

output "log_archive_bucket" {
  description = "Immutable audit log archive"
  value       = aws_s3_bucket.log_archive.id
}

output "object_lock_enabled" {
  description = "Whether the log archive is immutable"
  value       = var.log_object_lock
}

output "cui_kms_key" {
  description = "Customer managed key for CUI at rest"
  value       = aws_kms_key.cui.arn
}

output "logs_kms_key" {
  description = "Customer managed key for the audit archive"
  value       = aws_kms_key.logs.arn
}

output "cloudtrail_name" {
  description = "CloudTrail with log file validation"
  value       = aws_cloudtrail.enclave.name
}

output "fileserver_instance_id" {
  description = "Connect with: aws ssm start-session --target <id>"
  value       = var.enable_fileserver ? aws_instance.fileserver[0].id : "not created"
}

output "session_manager_command" {
  description = "Administrative access without an open port"
  value       = var.enable_fileserver ? "aws ssm start-session --target ${aws_instance.fileserver[0].id} --region ${data.aws_region.current.name}" : "not created"
}

output "baseline_findings_present" {
  description = "Whether the deliberate pre-remediation findings exist"
  value       = var.enable_baseline_findings
}

output "next_step" {
  description = "What to run after apply"
  value       = "cd scanner && python3 assess.py --region ${data.aws_region.current.name}"
}
