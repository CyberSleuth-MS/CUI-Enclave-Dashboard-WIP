# assess.py which is meant to update server.py
"""

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

# For dashboard
import requests
try:
    from reports_statuses import start_gap_report, finish_gap_report, set_gap_report_status
except ImportError:
    finish_gap_report = None
    set_gap_report_status = None
SERVER_URL = "http://127.0.0.1:8000"
VALID_STATUSES = {"pending", "active", "success", "warning", "failure"}

# For Updating The Phase Details mini-page (Terminals)
# NOT import asyncio
import sys, httpx
TERMINAL_URL = "http://127.0.0.1:8000/api/terminal/output"


class TerminalOutput:
    def __init__(self, phase_id, original):
        self.phase_id = phase_id
        self.original = original
        self.buffer = ""
        self.client = httpx.Client(timeout=2)

    def write(self, text):
        self.original.write(text)
        self.original.flush()
        self.buffer += text

        while "\n" in self.buffer:
            line, self.buffer = self.buffer.split("\n", 1)
            self.send(line.rstrip("\r"))
        return len(text)

    def flush(self):
        self.original.flush()

    def send(self, line):
        if not line:
            return
        try:
            self.client.post(TERMINAL_URL, json={"phase_id": self.phase_id, "line": line})
        except httpx.HTTPError:
            pass


def update_step(phase_id, step_id, status=None, label=None, message=None):
    data = {k: v for k, v in {"status": status, "label": label, "message": message}.items() if v is not None}

    response = httpx.patch(f"{SERVER_URL}/api/phases/{phase_id}/steps/{step_id}", json=data)
    #print("STATUS:", response.status_code, flush=True)
    #print("RESPONSE:", response.text, flush=True)
    response.raise_for_status()

    with open("data.json", "w", encoding="utf-8") as file:
        json.dump(response.json(), file, indent=4)

    return response.json()


def add_step(phase_id, step_id, label, status="pending", message=None):
    response = httpx.post(
        f"{SERVER_URL}/api/phases/{phase_id}/steps",
        json={"id": step_id, "label": label, "status": status, "message": message},
    )
    if response.status_code == 409:  # already exists, so just visually reset it when replaying or reloading the live sim
        return update_step(phase_id, step_id, status=status, label=label, message=message or "")
    response.raise_for_status()
    return response.json()


def remove_step(phase_id, step_id):
    response = httpx.delete(f"{SERVER_URL}/api/phases/{phase_id}/steps/{step_id}")
    response.raise_for_status()
    return response.json()


def add_phase(phase_id, title, file=None, background=None):
    response = httpx.post(
        f"{SERVER_URL}/api/phases",
        json={"id": phase_id, "title": title, "file": file, "background": background, "steps": []},
    )
    if response.status_code == 409:  # already exists, so just visually reset it when replaying or reloading the live sim
        return update_phase(phase_id, title=title, file=file, background=background)
    response.raise_for_status()
    return response.json()


def update_phase(phase_id, status=None, title=None, file=None, background=None):
    data = {
        k: v for k, v in {
            "status": status,
            "title": title,
            "file": file,
            "background": background
        }.items() if v is not None
    }
    response = httpx.patch(f"{SERVER_URL}/api/phases/{phase_id}", json=data)
    response.raise_for_status()
    return response.json()


def remove_phase(phase_id):
    response = httpx.delete(f"{SERVER_URL}/api/phases/{phase_id}")
    response.raise_for_status()
    return response.json()


add_phase("accesscontrol111", "Access Control", "monitor.html", "access-control.jpg")


# For AWS Profile Override, otherwise I kept getting InvalidClientTokenId
# Uses .env (my .gitignore ignores my .env from being uploaded.) For anyone reading: NEVER upload your .env!
# The .env shown on GitHub is an example for you to update yourself if you want to. It comes from AWS SSO [profile]
import os, subprocess
from dotenv import load_dotenv
load_dotenv()

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
ACCESS_PHASE = "accesscontrol111"
ACCESS_DENIED_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}
# Tracks whether 3.1.1 failed, so 3.1.22 can decide the final phase status
failure_in_check_3_1_1 = False


# Access Control [1/2]
def check_3_1_1(session):
    """Authorized users: no root access keys, no stale user access keys."""
    global failure_in_check_3_1_1
    failure_in_check_3_1_1 = False  # reset for replays / repeated runs

    update_phase(ACCESS_PHASE, status="active")

    add_step(ACCESS_PHASE, "has-root-access", "Evaluating Root Access Keys Present")
    add_step(ACCESS_PHASE, "has-super-old-root-access", "Flagging Old Or Expired Account Access Keys")
    # Pre-register 3.1.22's step so the phase doesn't briefly look "complete"
    # between the two checks (add_step resets it to pending if it already exists)
    add_step(ACCESS_PHASE, "has-public-buckets", "Evaluating if S3 Bucket(s) are mistakenly granted Public Access")

    iam = session.client("iam")
    findings, evidence = [], {}

    try:
        summary = iam.get_account_summary()["SummaryMap"]
        evidence["account_summary"] = {
            k: summary.get(k)
            for k in ("AccountAccessKeysPresent", "Users", "AccountMFAEnabled")
        }
        if summary.get("AccountAccessKeysPresent", 0) > 0:
            findings.append("Root account has active access keys")
            update_step(ACCESS_PHASE, "has-root-access",
                        label="Root Account Privileged Access Keys Present",
                        status="failure")
        else:
            update_step(ACCESS_PHASE, "has-root-access",
                        label="Root Account has limited access privileges",
                        status="success")

        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        stale = []

        for user in iam.list_users().get("Users", []):
            for key in iam.list_access_keys(
                UserName=user["UserName"]
            ).get("AccessKeyMetadata", []):
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
            update_step(ACCESS_PHASE, "has-super-old-root-access",
                        label=f"{len(stale)} Users Access Keys Present are older than 90 days, and need to be renewed",
                        status="failure")
        else:
            update_step(ACCESS_PHASE, "has-super-old-root-access",
                        label="Users Access Keys Present <90 Days",
                        status="success")
    except ClientError as exc:
        failure_in_check_3_1_1 = True
        code = exc.response.get("Error", {}).get("Code", "")
        step_ids = ("has-root-access", "has-super-old-root-access")
        if code in ACCESS_DENIED_CODES:
            msg = "Insufficient IAM permissions to perform access key compliance checks"
            for sid in step_ids:
                update_step(ACCESS_PHASE, sid, status="failure", message=msg)
            # 3.1.22 still has to run, so keep the phase non-final for now
            update_phase(ACCESS_PHASE, status="pending")
            return Result("3.1.1", Result.FAIL, [f"ClientError: {msg}"], evidence)
        # Unexpected AWS error: don't leave the steps spinning, then let main() record ERROR
        for sid in step_ids:
            update_step(ACCESS_PHASE, sid, status="warning", message=f"Could not assess: {code}")
        raise

    status = Result.PASS if not findings else Result.FAIL
    if status == Result.FAIL:
        failure_in_check_3_1_1 = True
    # Pending because this phase still has to run check_3_1_22
    update_phase(ACCESS_PHASE, status="pending")
    return Result("3.1.1", status, findings, evidence)


# Access Control [2/2]
def check_3_1_22(session):
    """Publicly accessible systems: block public access on every bucket."""
    update_phase(ACCESS_PHASE, status="active")
    add_step(ACCESS_PHASE, "has-public-buckets", "Evaluating if S3 Bucket(s) are mistakenly granted Public Access")

    s3 = session.client("s3")
    findings, evidence = [], {}
    offenders = []

    try:
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
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ACCESS_DENIED_CODES:
            msg = "Insufficient S3 permissions to perform public access checks"
            update_step(ACCESS_PHASE, "has-public-buckets", status="failure", message=msg)
            update_phase(ACCESS_PHASE, status="failure")
            return Result("3.1.22", Result.FAIL, [f"ClientError: {msg}"], evidence)

        update_step(ACCESS_PHASE, "has-public-buckets", status="warning",
                    message=f"Could not assess: {code}")
        update_phase(ACCESS_PHASE, status="failure")
        raise

    evidence["buckets_without_full_block"] = offenders

    if offenders:
        findings.append(
            f"{len(offenders)} bucket(s) without full public access block: "
            + "; ".join(offenders)
        )
        update_step(ACCESS_PHASE, "has-public-buckets",
                    label=f"{len(offenders)} S3 Bucket(s) [ {', '.join(offenders)} ] mistakenly granted Public Access",
                    status="failure")
    else:
        update_step(ACCESS_PHASE, "has-public-buckets",
                    label="S3 Bucket(s) are correctly configured for Private Access only",
                    status="success")

    status = Result.PASS if not findings else Result.FAIL

    if status == Result.PASS and not failure_in_check_3_1_1:
        update_phase(ACCESS_PHASE, status="success")
    else:
        update_phase(ACCESS_PHASE, status="failure")
    return Result("3.1.22", status, findings, evidence)


# Audit and Accountability
def check_3_3_1(session):
    """Audit logs: multi-region trail, logging, log file validation."""
    phase = "auditaccountability"
    add_phase(phase, "Audit and Accountability", "monitor.html", "aaa.jpg")
    update_phase(phase, status="active")

    add_step(phase, "has-trail", "Evaluating CloudTrail Trail Exists")
    add_step(phase, "has-qualifying-trail", "Verifying Trail Is Multi-Region, Logging, And Validated")

    ct = session.client("cloudtrail")
    findings, evidence = [], {}

    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        if not trails:
            update_step(phase, "has-trail", label="No CloudTrail Trail Exists", status="failure")
            update_step(phase, "has-qualifying-trail", label="No Trail Available To Validate", status="failure")
            update_phase(phase, status="failure")
            return Result("3.3.1", Result.FAIL, ["No CloudTrail trail exists"], {})

        update_step(phase, "has-trail", label=f"{len(trails)} CloudTrail Trail(s) Exist", status="success")

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
            update_step(phase, "has-qualifying-trail",
                        label=f"{len(evidence)} Trail(s) Found, None Are Multi-Region, Logging, And Validated",
                        message="; ".join(findings),
                        status="failure")
        else:
            update_step(phase, "has-qualifying-trail",
                        label="Multi-Region Trail With Logging And Log File Validation Present",
                        status="success")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        step_ids = ("has-trail", "has-qualifying-trail")
        if code in ACCESS_DENIED_CODES:
            msg = "Insufficient CloudTrail permissions to perform audit log checks"
            for sid in step_ids:
                update_step(phase, sid, status="failure", message=msg)
            update_phase(phase, status="failure")
            return Result("3.3.1", Result.FAIL, [f"ClientError: {msg}"], evidence)
        for sid in step_ids:
            update_step(phase, sid, status="warning", message=f"Could not assess: {code}")
        update_phase(phase, status="warning")
        raise

    status = Result.PASS if qualifying else Result.FAIL
    update_phase(phase, status="success" if status == Result.PASS else "failure")
    return Result("3.3.1", status, findings, evidence)


# Configuration Management
def check_3_4_7(session):
    """Nonessential ports: nothing open to the world."""
    phase = "configurationmanagement"
    add_phase(phase, "Configuration Management", "monitor.html", "cfgm.jpg")
    update_phase(phase, status="active")

    add_step(phase, "has-open-admin-ports", "Evaluating Security Groups For World-Open SSH, RDP, Or All Ports")
    add_step(phase, "has-open-other-ports", "Evaluating Security Groups For Other World-Open Ports")

    ec2 = session.client("ec2")
    findings, evidence = [], {}
    open_rules = []

    try:
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
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        step_ids = ("has-open-admin-ports", "has-open-other-ports")
        if code in ACCESS_DENIED_CODES:
            msg = "Insufficient EC2 permissions to perform security group checks"
            for sid in step_ids:
                update_step(phase, sid, status="failure", message=msg)
            update_phase(phase, status="failure")
            return Result("3.4.7", Result.FAIL, [f"ClientError: {msg}"], evidence)
        for sid in step_ids:
            update_step(phase, sid, status="warning", message=f"Could not assess: {code}")
        update_phase(phase, status="warning")
        raise

    evidence["open_to_world"] = open_rules
    for rule in open_rules:
        findings.append(
            f"[{rule['severity']}] {rule['group_id']} ({rule['group_name']}) "
            f"allows {rule['ports']} from {rule['source']}"
        )

    high = [r for r in open_rules if r["severity"] == "HIGH"]
    medium = [r for r in open_rules if r["severity"] == "MEDIUM"]

    if high:
        update_step(phase, "has-open-admin-ports",
                    label=f"{len(high)} Security Group Rule(s) Expose SSH, RDP, Or All Ports To The World",
                    message="; ".join(f"{r['group_id']} ({r['ports']})" for r in high),
                    status="failure")
    else:
        update_step(phase, "has-open-admin-ports",
                    label="No SSH, RDP, Or All-Port Rules Open To The World",
                    status="success")

    if medium:
        update_step(phase, "has-open-other-ports",
                    label=f"{len(medium)} Security Group Rule(s) Expose Other Ports To The World",
                    message="; ".join(f"{r['group_id']} ({r['ports']})" for r in medium),
                    status="failure")
    else:
        update_step(phase, "has-open-other-ports",
                    label="No Other Ports Open To The World",
                    status="success")

    status = Result.PASS if not open_rules else Result.FAIL
    update_phase(phase, status="success" if status == Result.PASS else "failure")
    return Result("3.4.7", status, findings, evidence)


# Identification and Authentication
def check_3_5_3(session):
    """Multifactor authentication, with partial credit."""
    phase = "identificationauthentication"
    add_phase(phase, "Identification and Authentication", "monitor.html", "iam.jpg")
    update_phase(phase, status="active")

    add_step(phase, "has-root-mfa", "Evaluating Root Account MFA")
    add_step(phase, "has-console-user-mfa", "Evaluating MFA For Console Users")

    iam = session.client("iam")
    findings, evidence = [], {}

    try:
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
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        step_ids = ("has-root-mfa", "has-console-user-mfa")
        if code in ACCESS_DENIED_CODES:
            msg = "Insufficient IAM permissions to perform MFA compliance checks"
            for sid in step_ids:
                update_step(phase, sid, status="failure", message=msg)
            update_phase(phase, status="failure")
            return Result("3.5.3", Result.FAIL, [f"ClientError: {msg}"], evidence)
        for sid in step_ids:
            update_step(phase, sid, status="warning", message=f"Could not assess: {code}")
        update_phase(phase, status="warning")
        raise

    # Identity Center users are not IAM users and do not appear above.
    # Enforcement there is an account setting, reported for context.
    try:
        sso = session.client("sso-admin")
        instances = sso.list_instances().get("Instances", [])
        evidence["identity_center_instances"] = len(instances)
    except (ClientError, Exception):
        evidence["identity_center_instances"] = "not queryable"

    if root_mfa:
        update_step(phase, "has-root-mfa", label="Root Account MFA Enabled", status="success")
    else:
        update_step(phase, "has-root-mfa", label="Root Account Does Not Have MFA Enabled", status="failure")

    if console_users_without_mfa:
        update_step(phase, "has-console-user-mfa",
                    label=f"{len(console_users_without_mfa)} Console User(s) Without MFA",
                    message=", ".join(console_users_without_mfa),
                    status="warning" if root_mfa else "failure")
    else:
        update_step(phase, "has-console-user-mfa", label="All Console Users Have MFA Enabled", status="success")

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

    if status == Result.PASS:
        update_phase(phase, status="success")
    elif status == Result.PARTIAL:
        update_phase(phase, status="warning")
    else:
        update_phase(phase, status="failure")
    return Result("3.5.3", status, findings, evidence)


# System and Communications Protection [1/2]
# Tracks 3.13.11's outcome, so 3.13.16 can decide the final phase status
status_of_check_3_13_11 = None


def check_3_13_11(session):
    """FIPS validated cryptography, with partial credit."""
    global status_of_check_3_13_11
    status_of_check_3_13_11 = None  # reset for replays / repeated runs

    phase = "systemcommunicationsprotection"
    add_phase(phase, "System and Communications Protection", "monitor.html", "syp.jpg")
    update_phase(phase, status="active")

    add_step(phase, "has-customer-keys", "Evaluating Customer Managed KMS Keys Present")
    add_step(phase, "has-key-rotation", "Verifying Automatic Key Rotation Is Enabled")
    # Pre-register 3.13.16's steps so the phase doesn't briefly look "complete"
    # between the two checks (add_step resets them to pending if they already exist)
    add_step(phase, "has-unencrypted-volumes", "Evaluating EBS Volume Encryption")
    add_step(phase, "has-unencrypted-buckets", "Evaluating S3 Bucket KMS Encryption")

    kms = session.client("kms")
    findings, evidence = [], {}

    customer_keys, no_rotation = [], []
    try:
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
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        step_ids = ("has-customer-keys", "has-key-rotation")
        if code in ACCESS_DENIED_CODES:
            status_of_check_3_13_11 = Result.FAIL
            msg = "Insufficient KMS permissions to perform encryption key checks"
            for sid in step_ids:
                update_step(phase, sid, status="failure", message=msg)
            # 3.13.16 still has to run, so keep the phase non-final for now
            update_phase(phase, status="pending")
            return Result("3.13.11", Result.FAIL, [f"ClientError: {msg}"], evidence)
        status_of_check_3_13_11 = Result.ERROR
        for sid in step_ids:
            update_step(phase, sid, status="warning", message=f"Could not assess: {code}")
        raise

    evidence["customer_managed_keys"] = len(customer_keys)
    evidence["keys_without_rotation"] = no_rotation

    if not customer_keys:
        findings.append(
            "No customer managed KMS keys. AWS managed keys give no key policy "
            "control and cannot support the 22 C.F.R. 120.54 position."
        )
        update_step(phase, "has-customer-keys", label="No Customer Managed KMS Keys Present", status="failure")
        update_step(phase, "has-key-rotation", label="No Customer Managed Keys To Evaluate Rotation For", status="failure")
        status = Result.FAIL
    elif no_rotation:
        findings.append(
            f"{len(no_rotation)} customer managed key(s) without automatic rotation: "
            + ", ".join(k[:8] + "..." for k in no_rotation)
        )
        findings.append(
            "Partial credit: encryption in place, key lifecycle incomplete"
        )
        update_step(phase, "has-customer-keys",
                    label=f"{len(customer_keys)} Customer Managed KMS Key(s) Present",
                    status="success")
        update_step(phase, "has-key-rotation",
                    label=f"{len(no_rotation)} Customer Managed Key(s) Without Automatic Rotation",
                    message=", ".join(k[:8] + "..." for k in no_rotation),
                    status="warning")
        status = Result.PARTIAL
    else:
        update_step(phase, "has-customer-keys",
                    label=f"{len(customer_keys)} Customer Managed KMS Key(s) Present",
                    status="success")
        update_step(phase, "has-key-rotation", label="All Customer Managed Keys Rotate Automatically", status="success")
        status = Result.PASS

    if status == Result.PASS:
        findings.append(
            "NOTE: key material is FIPS 140-2/140-3 validated, but calls must use "
            "the FIPS endpoints for the full path to qualify. Verify endpoint "
            "configuration manually."
        )

    status_of_check_3_13_11 = status
    # Pending because this phase still has to run check_3_13_16
    update_phase(phase, status="pending")
    return Result("3.13.11", status, findings, evidence)


# System and Communications Protection [2/2]
def check_3_13_16(session):
    """CUI at rest: encrypted volumes and encrypted buckets."""
    phase = "systemcommunicationsprotection"
    update_phase(phase, status="active")
    add_step(phase, "has-unencrypted-volumes", "Evaluating EBS Volume Encryption")
    add_step(phase, "has-unencrypted-buckets", "Evaluating S3 Bucket KMS Encryption")

    ec2 = session.client("ec2")
    s3 = session.client("s3")
    findings, evidence = [], {}

    unencrypted_volumes = []
    buckets_without_cmk = []

    try:
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for vol in page["Volumes"]:
                if not vol.get("Encrypted"):
                    unencrypted_volumes.append(vol["VolumeId"])

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
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        step_ids = ("has-unencrypted-volumes", "has-unencrypted-buckets")
        if code in ACCESS_DENIED_CODES:
            msg = "Insufficient EC2/S3 permissions to perform encryption at rest checks"
            for sid in step_ids:
                update_step(phase, sid, status="failure", message=msg)
            update_phase(phase, status="failure")
            return Result("3.13.16", Result.FAIL, [f"ClientError: {msg}"], evidence)
        for sid in step_ids:
            update_step(phase, sid, status="warning", message=f"Could not assess: {code}")
        update_phase(phase, status="warning")
        raise

    evidence["unencrypted_volumes"] = unencrypted_volumes
    if unencrypted_volumes:
        findings.append(
            f"{len(unencrypted_volumes)} unencrypted EBS volume(s): "
            + ", ".join(unencrypted_volumes)
        )
        update_step(phase, "has-unencrypted-volumes",
                    label=f"{len(unencrypted_volumes)} Unencrypted EBS Volume(s)",
                    message=", ".join(unencrypted_volumes),
                    status="failure")
    else:
        update_step(phase, "has-unencrypted-volumes", label="All EBS Volumes Are Encrypted", status="success")

    evidence["buckets_without_kms"] = buckets_without_cmk
    if buckets_without_cmk:
        findings.append(
            f"{len(buckets_without_cmk)} bucket(s) not using a KMS key: "
            + "; ".join(buckets_without_cmk)
        )
        update_step(phase, "has-unencrypted-buckets",
                    label=f"{len(buckets_without_cmk)} S3 Bucket(s) Not Using A KMS Key",
                    message="; ".join(buckets_without_cmk),
                    status="failure")
    else:
        update_step(phase, "has-unencrypted-buckets", label="All S3 Buckets Use KMS Encryption", status="success")

    status = Result.PASS if not findings else Result.FAIL

    if status == Result.FAIL or status_of_check_3_13_11 == Result.FAIL:
        update_phase(phase, status="failure")
    elif status_of_check_3_13_11 in (Result.PARTIAL, Result.ERROR):
        update_phase(phase, status="warning")
    else:
        update_phase(phase, status="success")
    return Result("3.13.16", status, findings, evidence)


# System and Information Integrity
def check_3_14_6(session):
    """Monitoring: GuardDuty plus flow logs on every VPC."""
    phase = "systeminformationintegrity"
    add_phase(phase, "System and Information Integrity", "monitor.html", "sii.jpg")
    update_phase(phase, status="active")

    add_step(phase, "has-guardduty", "Evaluating GuardDuty Is Enabled")
    add_step(phase, "has-flow-logs", "Evaluating VPC Flow Logs Are Active")

    findings, evidence = [], {}

    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        enabled = []
        for det in detectors:
            detail = gd.get_detector(DetectorId=det)
            if detail.get("Status") == "ENABLED":
                enabled.append(det)
        evidence["guardduty_detectors_enabled"] = len(enabled)

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
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        step_ids = ("has-guardduty", "has-flow-logs")
        if code in ACCESS_DENIED_CODES:
            msg = "Insufficient GuardDuty/EC2 permissions to perform monitoring checks"
            for sid in step_ids:
                update_step(phase, sid, status="failure", message=msg)
            update_phase(phase, status="failure")
            return Result("3.14.6", Result.FAIL, [f"ClientError: {msg}"], evidence)
        for sid in step_ids:
            update_step(phase, sid, status="warning", message=f"Could not assess: {code}")
        update_phase(phase, status="warning")
        raise

    if not enabled:
        findings.append("GuardDuty is not enabled in this region")
        update_step(phase, "has-guardduty", label="GuardDuty Is Not Enabled In This Region", status="failure")
    else:
        update_step(phase, "has-guardduty", label="GuardDuty Is Enabled", status="success")

    if unmonitored:
        findings.append(
            f"{len(unmonitored)} VPC(s) without active flow logs: "
            + ", ".join(unmonitored)
        )
        update_step(phase, "has-flow-logs",
                    label=f"{len(unmonitored)} VPC(s) Without Active Flow Logs",
                    message=", ".join(unmonitored),
                    status="failure")
    else:
        update_step(phase, "has-flow-logs", label="All VPCs Have Active Flow Logs", status="success")

    status = Result.PASS if not findings else Result.FAIL
    update_phase(phase, status="success" if status == Result.PASS else "failure")
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
    parser.add_argument("--profile", default=os.getenv("PROFILE_TO_USE") or None, help="AWS profile name")
    parser.add_argument("--json", dest="json_out", help="Write JSON results here")
    parser.add_argument("--report", help="Write a markdown gap report here")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    # ------------------------------------------------------------------
    # AWS Authentication (automatic SSO refresh)
    # ------------------------------------------------------------------
    def create_session():
        return boto3.Session(
            profile_name=args.profile,
            region_name=args.region
        )

    def login_sso():
        print("\nAWS credentials expired or unavailable.")
        print("Refreshing AWS SSO session...\n")
        command = ["aws", "sso", "login"]
        if args.profile:
            command.extend(["--profile", args.profile])
        try:
            subprocess.run(command, check=True)
        except subprocess.CalledProcessError as exc:
            sys.exit(f"AWS SSO login failed: {exc}")
            
    try:
        session = create_session()
        account = session.client("sts").get_caller_identity()["Account"]
    except Exception as exc:
        print(f"AWS authentication error: {exc}")
        login_sso()
        session = create_session()
        try:
            account = session.client("sts").get_caller_identity()["Account"]
        except Exception as retry_exc:
            sys.exit(f"AWS authentication failed after SSO login: {retry_exc}")
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code")
        if error_code == "ExpiredToken":
            print("AWS token expired.")
            login_sso()
            session = create_session()
            try:
                account = session.client("sts").get_caller_identity()["Account"]
            except Exception as retry_exc:
                sys.exit(f"AWS authentication failed after SSO login: {retry_exc}")
        else:
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
        try:
            start_gap_report(SERVER_URL)
        except Exception:
            try:
                set_gap_report_status("error", SERVER_URL)
            except Exception:
                print("WARNING: Gap Report status module unavailable; completion unable to be reported.")
            raise
            print()
        write_markdown(args.report, results, summary, account, args.region)
        print(f"  Gap report:   {args.report}")
        try:
            finish_gap_report(SERVER_URL)
        except Exception:
            try:
                set_gap_report_status("error", SERVER_URL)
            except Exception:
                print("WARNING: Gap Report status module unavailable; completion unable to be reported.")
            raise
            print()
    # Non-zero exit when a non-deferrable requirement fails, so the scan can
    # gate a pipeline later.
    blocking = [r for r in results if "MUST REMEDIATE" in r.deferrable]
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())

