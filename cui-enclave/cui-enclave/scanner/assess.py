#!/usr/bin/env python3
"""
NIST SP 800-171 automated assessment tool
CYBR 4350 Capstone - Team 3

Reads live AWS configuration through the AWS API and scores the selected
requirements using the DoD Assessment Methodology (Version 1.2.1) weights.

The tool reads configuration state. It does not change anything, and the
IAM permissions it needs are read-only. A compliance scanner that requires
write access is a liability.

Usage:
    python3 assess.py --region us-east-2
    python3 assess.py --region us-east-2 --json results.json --report gap-report.md
"""

import argparse
import json
import sys
from datetime import datetime, timezone, timedelta

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    sys.exit("boto3 is required:  pip install boto3")


# --------------------------------------------------------------------------
# Requirement catalog
#
# Point values are from the NIST SP 800-171 DoD Assessment Methodology,
# Version 1.2.1. Only requirements weighted at 1 point may be placed on a
# Plan of Action and Milestones under 32 C.F.R. 170.21, with a single
# exception allowing 3.13.11 to be deferred at 3 points when encryption is
# in use but the module is not FIPS validated.
# --------------------------------------------------------------------------

REQUIREMENTS = {
    "3.1.1": {
        "family": "Access Control",
        "weight": 5,
        "partial": None,
        "text": "Limit system access to authorized users, processes acting for users, and devices",
    },
    "3.1.22": {
        "family": "Access Control",
        "weight": 1,
        "partial": None,
        "text": "Control CUI posted or processed on publicly accessible systems",
    },
    "3.3.1": {
        "family": "Audit and Accountability",
        "weight": 5,
        "partial": None,
        "text": "Create and retain audit logs sufficient to monitor, analyze, investigate, and report unauthorized activity",
    },
    "3.4.7": {
        "family": "Configuration Management",
        "weight": 5,
        "partial": None,
        "text": "Restrict, disable, or prevent use of nonessential programs, functions, ports, protocols, and services",
    },
    "3.5.3": {
        "family": "Identification and Authentication",
        "weight": 5,
        "partial": 3,
        "text": "Use multifactor authentication for local and network access to privileged accounts and network access to non-privileged accounts",
    },
    "3.13.11": {
        "family": "System and Communications Protection",
        "weight": 5,
        "partial": 3,
        "text": "Employ FIPS validated cryptography when used to protect the confidentiality of CUI",
    },
    "3.13.16": {
        "family": "System and Communications Protection",
        "weight": 1,
        "partial": None,
        "text": "Protect the confidentiality of CUI at rest",
    },
    "3.14.6": {
        "family": "System and Information Integrity",
        "weight": 5,
        "partial": None,
        "text": "Monitor systems, including inbound and outbound traffic, to detect attacks and indicators of potential attacks",
    },
}

TOTAL_REQUIREMENTS = 110
STARTING_SCORE = 110


class Result:
    """One requirement's verdict, with the evidence behind it."""

    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    ERROR = "ERROR"

    def __init__(self, req_id, status, findings=None, evidence=None):
        self.req_id = req_id
        self.status = status
        self.findings = findings or []
        self.evidence = evidence or {}
        self.checked_at = datetime.now(timezone.utc).isoformat()

    @property
    def deduction(self):
        req = REQUIREMENTS[self.req_id]
        if self.status == Result.PASS:
            return 0
        if self.status == Result.PARTIAL and req["partial"]:
            return req["partial"]
        if self.status == Result.ERROR:
            return 0  # cannot assess, reported separately rather than scored
        return req["weight"]

    @property
    def deferrable(self):
        """POA&M eligibility under 32 C.F.R. 170.21."""
        req = REQUIREMENTS[self.req_id]
        if self.status == Result.PASS:
            return "n/a"
        if self.req_id == "3.13.11" and self.status == Result.PARTIAL:
            return "POA&M eligible at 3 points"
        if req["weight"] == 1:
            return "POA&M eligible"
        return "MUST REMEDIATE before assessment"


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------


def check_3_1_1(session):
    """Authorized users: no root access keys, no stale user access keys."""
    iam = session.client("iam")
    findings, evidence = [], {}

    summary = iam.get_account_summary()["SummaryMap"]
    evidence["account_summary"] = {
        k: summary.get(k)
        for k in ("AccountAccessKeysPresent", "Users", "AccountMFAEnabled")
    }

    if summary.get("AccountAccessKeysPresent", 0) > 0:
        findings.append("Root account has active access keys")

    cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    stale = []
    for user in iam.list_users().get("Users", []):
        for key in iam.list_access_keys(UserName=user["UserName"]).get(
            "AccessKeyMetadata", []
        ):
            if key["Status"] == "Active" and key["CreateDate"] < cutoff:
                stale.append(
                    f"{user['UserName']}:{key['AccessKeyId'][-4:]} "
                    f"({(datetime.now(timezone.utc) - key['CreateDate']).days}d old)"
                )
    evidence["stale_access_keys"] = stale
    if stale:
        findings.append(
            f"{len(stale)} long lived access key(s) older than 90 days: {', '.join(stale)}"
        )

    status = Result.PASS if not findings else Result.FAIL
    return Result("3.1.1", status, findings, evidence)


def check_3_1_22(session):
    """Publicly accessible systems: block public access on every bucket."""
    s3 = session.client("s3")
    findings, evidence = [], {}
    offenders = []

    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        try:
            cfg = s3.get_public_access_block(Bucket=name)[
                "PublicAccessBlockConfiguration"
            ]
        except ClientError as exc:
            if exc.response["Error"]["Code"] in (
                "NoSuchPublicAccessBlockConfiguration",
                "AccessDenied",
            ):
                offenders.append(f"{name} (no public access block configured)")
                continue
            raise

        missing = [k for k, v in cfg.items() if not v]
        if missing:
            offenders.append(f"{name} (disabled: {', '.join(missing)})")

    evidence["buckets_without_full_block"] = offenders
    if offenders:
        findings.append(
            f"{len(offenders)} bucket(s) without full public access block: "
            + "; ".join(offenders)
        )

    status = Result.PASS if not findings else Result.FAIL
    return Result("3.1.22", status, findings, evidence)


def check_3_3_1(session):
    """Audit logs: multi-region trail, logging, log file validation."""
    ct = session.client("cloudtrail")
    findings, evidence = [], {}

    trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
    if not trails:
        return Result("3.3.1", Result.FAIL, ["No CloudTrail trail exists"], {})

    qualifying = []
    for trail in trails:
        name = trail["Name"]
        status = ct.get_trail_status(Name=trail["TrailARN"])
        detail = {
            "name": name,
            "multi_region": trail.get("IsMultiRegionTrail", False),
            "log_file_validation": trail.get("LogFileValidationEnabled", False),
            "kms_encrypted": bool(trail.get("KmsKeyId")),
            "is_logging": status.get("IsLogging", False),
        }
        evidence[name] = detail
        if all(
            (
                detail["multi_region"],
                detail["log_file_validation"],
                detail["is_logging"],
            )
        ):
            qualifying.append(name)

    if not qualifying:
        for name, d in evidence.items():
            gaps = [
                k
                for k in ("multi_region", "log_file_validation", "is_logging")
                if not d[k]
            ]
            findings.append(f"Trail {name} missing: {', '.join(gaps)}")

    status = Result.PASS if qualifying else Result.FAIL
    return Result("3.3.1", status, findings, evidence)


def check_3_4_7(session):
    """Nonessential ports: nothing open to the world."""
    ec2 = session.client("ec2")
    findings, evidence = [], {}
    open_rules = []

    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            for perm in sg.get("IpPermissions", []):
                world = [
                    r["CidrIp"]
                    for r in perm.get("IpRanges", [])
                    if r["CidrIp"] == "0.0.0.0/0"
                ] + [
                    r["CidrIpv6"]
                    for r in perm.get("Ipv6Ranges", [])
                    if r["CidrIpv6"] == "::/0"
                ]
                if not world:
                    continue
                from_p = perm.get("FromPort", "all")
                to_p = perm.get("ToPort", "all")
                proto = perm.get("IpProtocol", "-1")
                port_desc = (
                    "all ports"
                    if proto == "-1"
                    else (f"{from_p}" if from_p == to_p else f"{from_p}-{to_p}")
                )
                severity = (
                    "HIGH"
                    if from_p in (22, 3389) or proto == "-1"
                    else "MEDIUM"
                )
                open_rules.append(
                    {
                        "group_id": sg["GroupId"],
                        "group_name": sg["GroupName"],
                        "vpc_id": sg.get("VpcId"),
                        "protocol": proto,
                        "ports": port_desc,
                        "source": world[0],
                        "severity": severity,
                    }
                )

    evidence["open_to_world"] = open_rules
    for rule in open_rules:
        findings.append(
            f"[{rule['severity']}] {rule['group_id']} ({rule['group_name']}) "
            f"allows {rule['ports']} from {rule['source']}"
        )

    status = Result.PASS if not open_rules else Result.FAIL
    return Result("3.4.7", status, findings, evidence)


def check_3_5_3(session):
    """Multifactor authentication, with partial credit."""
    iam = session.client("iam")
    findings, evidence = [], {}

    summary = iam.get_account_summary()["SummaryMap"]
    root_mfa = bool(summary.get("AccountMFAEnabled", 0))
    evidence["root_mfa_enabled"] = root_mfa

    console_users_without_mfa = []
    for user in iam.list_users().get("Users", []):
        name = user["UserName"]
        try:
            iam.get_login_profile(UserName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchEntity":
                continue  # no console password, not in scope for this check
            raise
        if not iam.list_mfa_devices(UserName=name).get("MFADevices", []):
            console_users_without_mfa.append(name)

    evidence["console_users_without_mfa"] = console_users_without_mfa

    # Identity Center users are not IAM users and do not appear above.
    # Enforcement there is an account setting, reported for context.
    try:
        sso = session.client("sso-admin")
        instances = sso.list_instances().get("Instances", [])
        evidence["identity_center_instances"] = len(instances)
    except (ClientError, Exception):
        evidence["identity_center_instances"] = "not queryable"

    if not root_mfa:
        findings.append("Root account does not have MFA enabled")
        status = Result.FAIL
    elif console_users_without_mfa:
        findings.append(
            "MFA enforced for the root account but missing for "
            f"{len(console_users_without_mfa)} console user(s): "
            + ", ".join(console_users_without_mfa)
        )
        findings.append(
            "Partial credit: privileged access protected, general users not"
        )
        status = Result.PARTIAL
    else:
        status = Result.PASS

    return Result("3.5.3", status, findings, evidence)


def check_3_13_11(session):
    """FIPS validated cryptography, with partial credit."""
    kms = session.client("kms")
    findings, evidence = [], {}

    customer_keys, no_rotation = [], []
    paginator = kms.get_paginator("list_keys")
    for page in paginator.paginate():
        for key in page["Keys"]:
            try:
                meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
            except ClientError:
                continue
            if meta.get("KeyManager") != "CUSTOMER":
                continue
            if meta.get("KeyState") != "Enabled":
                continue
            customer_keys.append(meta["KeyId"])
            try:
                rotating = kms.get_key_rotation_status(KeyId=meta["KeyId"]).get(
                    "KeyRotationEnabled", False
                )
            except ClientError:
                rotating = False
            if not rotating:
                no_rotation.append(meta["KeyId"])

    evidence["customer_managed_keys"] = len(customer_keys)
    evidence["keys_without_rotation"] = no_rotation

    if not customer_keys:
        findings.append(
            "No customer managed KMS keys. AWS managed keys give no key policy "
            "control and cannot support the 22 C.F.R. 120.54 position."
        )
        status = Result.FAIL
    elif no_rotation:
        findings.append(
            f"{len(no_rotation)} customer managed key(s) without automatic rotation: "
            + ", ".join(k[:8] + "..." for k in no_rotation)
        )
        findings.append(
            "Partial credit: encryption in place, key lifecycle incomplete"
        )
        status = Result.PARTIAL
    else:
        status = Result.PASS

    if status == Result.PASS:
        findings.append(
            "NOTE: key material is FIPS 140-2/140-3 validated, but calls must use "
            "the FIPS endpoints for the full path to qualify. Verify endpoint "
            "configuration manually."
        )

    return Result("3.13.11", status, findings, evidence)


def check_3_13_16(session):
    """CUI at rest: encrypted volumes and encrypted buckets."""
    ec2 = session.client("ec2")
    s3 = session.client("s3")
    findings, evidence = [], {}

    unencrypted_volumes = []
    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate():
        for vol in page["Volumes"]:
            if not vol.get("Encrypted"):
                unencrypted_volumes.append(vol["VolumeId"])
    evidence["unencrypted_volumes"] = unencrypted_volumes
    if unencrypted_volumes:
        findings.append(
            f"{len(unencrypted_volumes)} unencrypted EBS volume(s): "
            + ", ".join(unencrypted_volumes)
        )

    buckets_without_cmk = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        try:
            rules = s3.get_bucket_encryption(Bucket=name)[
                "ServerSideEncryptionConfiguration"
            ]["Rules"]
        except ClientError:
            buckets_without_cmk.append(f"{name} (no default encryption)")
            continue
        algorithms = {
            r["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] for r in rules
        }
        if "aws:kms" not in algorithms:
            buckets_without_cmk.append(
                f"{name} (SSE-S3 only, not customer managed)"
            )

    evidence["buckets_without_kms"] = buckets_without_cmk
    if buckets_without_cmk:
        findings.append(
            f"{len(buckets_without_cmk)} bucket(s) not using a KMS key: "
            + "; ".join(buckets_without_cmk)
        )

    status = Result.PASS if not findings else Result.FAIL
    return Result("3.13.16", status, findings, evidence)


def check_3_14_6(session):
    """Monitoring: GuardDuty plus flow logs on every VPC."""
    findings, evidence = [], {}

    gd = session.client("guardduty")
    detectors = gd.list_detectors().get("DetectorIds", [])
    enabled = []
    for det in detectors:
        detail = gd.get_detector(DetectorId=det)
        if detail.get("Status") == "ENABLED":
            enabled.append(det)
    evidence["guardduty_detectors_enabled"] = len(enabled)
    if not enabled:
        findings.append("GuardDuty is not enabled in this region")

    ec2 = session.client("ec2")
    vpcs = [v["VpcId"] for v in ec2.describe_vpcs()["Vpcs"]]
    flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])
    monitored = {
        fl["ResourceId"]
        for fl in flow_logs
        if fl.get("FlowLogStatus") == "ACTIVE"
    }
    unmonitored = [v for v in vpcs if v not in monitored]
    evidence["vpcs"] = vpcs
    evidence["vpcs_without_flow_logs"] = unmonitored
    if unmonitored:
        findings.append(
            f"{len(unmonitored)} VPC(s) without active flow logs: "
            + ", ".join(unmonitored)
        )

    status = Result.PASS if not findings else Result.FAIL
    return Result("3.14.6", status, findings, evidence)


CHECKS = {
    "3.1.1": check_3_1_1,
    "3.1.22": check_3_1_22,
    "3.3.1": check_3_3_1,
    "3.4.7": check_3_4_7,
    "3.5.3": check_3_5_3,
    "3.13.11": check_3_13_11,
    "3.13.16": check_3_13_16,
    "3.14.6": check_3_14_6,
}


# --------------------------------------------------------------------------
# Scoring and reporting
# --------------------------------------------------------------------------


def score(results):
    deductions = sum(r.deduction for r in results)
    return {
        "starting_score": STARTING_SCORE,
        "total_deductions": deductions,
        "sprs_score": STARTING_SCORE - deductions,
        "requirements_assessed": len(results),
        "requirements_manual_review": TOTAL_REQUIREMENTS - len(results),
        "assumption": (
            f"Score assumes the {TOTAL_REQUIREMENTS - len(results)} requirements not "
            "automatically assessed are implemented. Those require policy or "
            "personnel evidence and are flagged for manual review."
        ),
        "conditional_threshold": 88,
        "meets_conditional_threshold": (STARTING_SCORE - deductions) >= 88,
    }


COLORS = {
    Result.PASS: "\033[92m",
    Result.FAIL: "\033[91m",
    Result.PARTIAL: "\033[93m",
    Result.ERROR: "\033[90m",
}
RESET = "\033[0m"


def print_console(results, summary, account, region, color=True):
    def c(status, text):
        return f"{COLORS[status]}{text}{RESET}" if color else text

    print()
    print("=" * 72)
    print("  NIST SP 800-171 ASSESSMENT")
    print(f"  Account {account}   Region {region}")
    print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 72)
    print()

    for r in results:
        req = REQUIREMENTS[r.req_id]
        weight = (
            f"{req['weight']}"
            if r.status != Result.PARTIAL or not req["partial"]
            else f"{req['partial']} of {req['weight']}"
        )
        print(f"  {c(r.status, r.status.ljust(8))} {r.req_id.ljust(9)} "
              f"{req['family']}")
        print(f"           {req['text'][:62]}")
        if r.status != Result.PASS:
            print(f"           Deduction: -{r.deduction} ({weight} point weight)")
            print(f"           POA&M: {r.deferrable}")
        for f in r.findings:
            print(f"           - {f}")
        print()

    print("-" * 72)
    print(f"  Starting score:        {summary['starting_score']}")
    print(f"  Total deductions:     -{summary['total_deductions']}")
    print(f"  SPRS SCORE:            {summary['sprs_score']}")
    print()
    print(f"  Assessed automatically: {summary['requirements_assessed']} requirements")
    print(f"  Manual review needed:   {summary['requirements_manual_review']} requirements")
    threshold = (
        "MEETS" if summary["meets_conditional_threshold"] else "BELOW"
    )
    print(f"  Conditional threshold (88): {threshold}")
    print("-" * 72)
    print()
    must_fix = [r for r in results if "MUST REMEDIATE" in r.deferrable]
    if must_fix:
        print("  Cannot be deferred to a POA&M, must be closed before assessment:")
        for r in must_fix:
            print(f"    {r.req_id}  (-{r.deduction})")
        print()


def write_markdown(path, results, summary, account, region):
    lines = [
        "# NIST SP 800-171 Assessment Report",
        "",
        f"**Account:** {account}  ",
        f"**Region:** {region}  ",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Methodology:** NIST SP 800-171 DoD Assessment Methodology, Version 1.2.1",
        "",
        "## Score",
        "",
        f"| | |",
        f"|---|---|",
        f"| Starting score | {summary['starting_score']} |",
        f"| Deductions | -{summary['total_deductions']} |",
        f"| **SPRS score** | **{summary['sprs_score']}** |",
        f"| Conditional threshold (88) | "
        f"{'Met' if summary['meets_conditional_threshold'] else 'Not met'} |",
        "",
        f"_{summary['assumption']}_",
        "",
        "## Findings",
        "",
        "| Requirement | Family | Status | Deduction | POA&M eligibility |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        req = REQUIREMENTS[r.req_id]
        lines.append(
            f"| {r.req_id} | {req['family']} | {r.status} | "
            f"-{r.deduction} | {r.deferrable} |"
        )

    lines += ["", "## Detail", ""]
    for r in results:
        req = REQUIREMENTS[r.req_id]
        lines += [f"### {r.req_id} - {req['family']}", "", f"> {req['text']}", ""]
        lines.append(f"**Status:** {r.status}  ")
        lines.append(f"**Point weight:** {req['weight']}  ")
        lines.append(f"**Deduction:** -{r.deduction}  ")
        lines.append(f"**POA&M:** {r.deferrable}  ")
        lines.append(f"**Checked:** {r.checked_at}")
        lines.append("")
        if r.findings:
            lines.append("**Findings**")
            lines.append("")
            for f in r.findings:
                lines.append(f"- {f}")
            lines.append("")
        lines.append("**Evidence**")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(r.evidence, indent=2, default=str))
        lines.append("```")
        lines.append("")

    with open(path, "w") as fh:
        fh.write("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(
        description="NIST SP 800-171 automated assessment"
    )
    parser.add_argument("--region", default="us-east-2")
    parser.add_argument("--profile", default=None, help="AWS profile name")
    parser.add_argument("--json", dest="json_out", help="Write JSON results here")
    parser.add_argument("--report", help="Write a markdown gap report here")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        account = session.client("sts").get_caller_identity()["Account"]
    except NoCredentialsError:
        sys.exit("No AWS credentials found. Run 'aws sso login' first.")
    except ClientError as exc:
        sys.exit(f"Could not authenticate: {exc}")

    results = []
    for req_id, check in CHECKS.items():
        try:
            results.append(check(session))
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            results.append(
                Result(
                    req_id,
                    Result.ERROR,
                    [f"Could not assess: {code}. Check read permissions."],
                    {"error": str(exc)},
                )
            )
        except Exception as exc:  # noqa: BLE001 - report rather than crash mid-scan
            results.append(
                Result(req_id, Result.ERROR, [f"Unexpected error: {exc}"], {})
            )

    summary = score(results)
    print_console(results, summary, account, args.region, color=not args.no_color)

    if args.json_out:
        payload = {
            "account": account,
            "region": args.region,
            "generated": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "results": [
                {
                    "requirement": r.req_id,
                    "family": REQUIREMENTS[r.req_id]["family"],
                    "text": REQUIREMENTS[r.req_id]["text"],
                    "weight": REQUIREMENTS[r.req_id]["weight"],
                    "status": r.status,
                    "deduction": r.deduction,
                    "poam_eligibility": r.deferrable,
                    "findings": r.findings,
                    "evidence": r.evidence,
                    "checked_at": r.checked_at,
                }
                for r in results
            ],
        }
        with open(args.json_out, "w") as fh:
            json.dump(payload, fh, indent=2, default=str)
        print(f"  JSON results: {args.json_out}")

    if args.report:
        write_markdown(args.report, results, summary, account, args.region)
        print(f"  Gap report:   {args.report}")

    print()
    # Non-zero exit when a non-deferrable requirement fails, so the scan can
    # gate a pipeline later.
    blocking = [r for r in results if "MUST REMEDIATE" in r.deferrable]
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
