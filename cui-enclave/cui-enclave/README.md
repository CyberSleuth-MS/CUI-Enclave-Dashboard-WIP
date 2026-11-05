# CUI Enclave + Automated NIST SP 800-171 Assessment

CYBR 4350 Capstone, Team 3. Terraform definition of a Controlled Unclassified
Information (CUI) enclave in Amazon Web Services (AWS), plus a Python tool that
scores the live environment against selected NIST SP 800-171 requirements using
the Department of Defense (DoD) Assessment Methodology weights.

---

## What this builds

| Component | Purpose | Requirement |
|---|---|---|
| Virtual Private Cloud (VPC), 10.0.0.0/16, **no internet gateway** | Enclave boundary with no path to the public internet | 3.13.1 |
| Four subnet tiers: access, endpoint, CUI workloads, CUI desktops | Each boundary is a control point | 3.13.5 |
| PrivateLink endpoints (S3 gateway, KMS, SSM x3) | Service access without leaving the AWS network | 3.13.1 |
| Two customer managed KMS keys, rotation enabled | Separate keys for CUI and for logs | 3.13.11, 3.13.16 |
| CUI bucket: KMS encrypted, versioned, public access blocked, TLS required | Data at rest | 3.13.16, 3.1.22 |
| Log archive: KMS encrypted, optional Object Lock | Tamper-evident evidence | 3.3.1 |
| CloudTrail: multi-region, log file validation, S3 data events | Audit trail | 3.3.1, 3.3.2 |
| AWS Config recorder + 6 managed rules | Baseline configuration | 3.4.1, 3.4.2 |
| GuardDuty + VPC Flow Logs | Threat detection and network record | 3.14.6 |
| EC2 fileserver: no public IP, **no inbound rules**, no SSH key | Session Manager only | 3.4.7, 3.1.12 |
| Deliberate baseline findings (toggleable) | Gives the scanner real gaps to catch | demo |

**Not built here, by design:** Client VPN, private certificate authority, and
WorkSpaces. Those are a multi-day build at roughly $500/month and are documented
as the production access path. Identity Center already demonstrates the
multifactor and least-privilege story they would carry.

---

## Prerequisites

```bash
# Terraform 1.5+
terraform -version

# AWS CLI signed in through Identity Center
aws sso login
aws sts get-caller-identity     # confirm the right account

# Python for the scanner
pip install boto3
```

The Terraform apply creates IAM roles, so it needs more than PowerUserAccess.
Run it under an AdministratorAccess permission set, or add `iam:CreateRole`,
`iam:AttachRolePolicy`, `iam:PutRolePolicy`, and `iam:PassRole` to a dedicated
permission set. The scanner only ever needs read access.

---

## Build

```bash
terraform init
terraform plan -out=tfplan      # review before applying
terraform apply tfplan
```

Roughly four to six minutes. The VPC endpoints are the slow part.

## Scan

```bash
cd scanner
python3 assess.py --region us-east-2
python3 assess.py --region us-east-2 --json results-baseline.json --report gap-report-baseline.md
```

## Remediate and rescan

```bash
cd ..
terraform apply -var="enable_baseline_findings=false"
cd scanner
python3 assess.py --region us-east-2 --json results-after.json --report gap-report-after.md
```

With the baseline findings present the score lands around 100. After
remediation it returns to 110. That delta, captured in two JSON files with
timestamps, is the demonstration.

## Tear down

```bash
terraform destroy
```

Run this whenever you are not actively working. See cost below.

---

## Cost

Nearly everything here is free or fractions of a cent. The exception is the
four PrivateLink interface endpoints, at about $0.01 per hour each.

| State | Cost |
|---|---|
| Fully deployed, left running | ~$1.00/day, ~$30/month |
| Deployed, interface endpoints off | ~$0.05/day |
| Destroyed | $0 |

```bash
# Build the network cheaply while iterating
terraform apply -var="enable_interface_endpoints=false" -var="enable_fileserver=false"
```

Set a billing alarm before the team starts working. Four people in one account
is exactly how a forgotten resource turns into a surprise.

---

## Variables worth knowing

| Variable | Default | Notes |
|---|---|---|
| `region` | `us-east-2` | Commercial region; production design targets GovCloud |
| `enable_interface_endpoints` | `true` | The only meaningful hourly cost |
| `enable_fileserver` | `true` | Needs endpoints for Session Manager |
| `enable_baseline_findings` | `true` | Set false to demonstrate remediation |
| `log_object_lock` | `false` | **Leave false while iterating.** See below |
| `enable_guardduty` | `true` | Set false if a detector already exists |

### About Object Lock

`log_object_lock = true` makes log objects immutable, which is the real
evidence-integrity control and worth a screenshot. It also means
`terraform destroy` may fail to empty the bucket, leaving you to clean it up by
hand after the retention period expires.

Build with it off. Turn it on for the final build and the demonstration, take
the screenshot, and keep the retention period at one day.

---

## Connecting to the fileserver

There is no SSH path. No key pair, no public IP, no inbound rules.

```bash
aws ssm start-session --target $(terraform output -raw fileserver_instance_id)
```

This is a stronger control than a bastion host: no port is open, and the whole
session is logged to CloudTrail. It is also a good live demo, because the
obvious question is "how do you get in if port 22 is closed," and this is the
answer.

---

## Demonstration sequence

Fifteen minutes, hits four rubric categories.

1. `terraform plan` — infrastructure as code, shows exactly what changes
2. `terraform apply` — environment built from a definition, not clicks
3. `aws ssm start-session` — administrative access with no open port
4. `python3 assess.py` — baseline scan, findings and a score
5. `terraform apply -var="enable_baseline_findings=false"` — remediation through code
6. `python3 assess.py` — rescan, score moves, findings cleared
7. Flow Logs in the archive showing the before and after

Record this. A screen recording of the full cycle cannot fail live, and it
covers core features, security controls, testing evidence, and tools
demonstrated.

---

## Layout

```
cui-enclave/
├── versions.tf      provider and version constraints
├── variables.tf     every toggle, with cost and risk notes
├── network.tf       VPC, subnets, routing, NACLs, flow logs
├── endpoints.tf     PrivateLink gateway and interface endpoints
├── kms.tf           two customer managed keys and their policies
├── s3.tf            CUI bucket and immutable log archive
├── logging.tf       CloudTrail, Config + rules, GuardDuty
├── compute.tf       fileserver, IAM role, security groups
├── baseline.tf      deliberate findings for the demo
├── outputs.tf       ids, names, and the next command to run
└── scanner/
    └── assess.py    the assessment tool
```

---

## What the scanner does

Queries IAM, EC2, S3, KMS, CloudTrail, and GuardDuty read-only, evaluates eight
requirements, applies the DoD Assessment Methodology weights, and prints a score
with a gap report.

It implements the two rules people get wrong:

- **Partial credit** exists for exactly two requirements, 3.5.3 and 3.13.11, and
  the tool scores 3 instead of 5 where the weaker condition is met.
- **POA&M eligibility** under 32 C.F.R. 170.21 covers only 1-point requirements,
  plus 3.13.11 at 3 points. Every failed 5-point requirement is labeled
  "MUST REMEDIATE before assessment" rather than deferrable.

It enumerates 8 of the 110 requirements automatically and reports the other 102
as requiring manual review. The printed score states that assumption explicitly
rather than hiding it.
