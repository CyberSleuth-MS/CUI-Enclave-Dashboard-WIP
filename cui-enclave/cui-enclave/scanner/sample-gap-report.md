# NIST SP 800-171 Assessment Report

**Account:** 123456789012  
**Region:** us-east-2  
**Generated:** 2026-10-27 23:33:59 UTC  
**Methodology:** NIST SP 800-171 DoD Assessment Methodology, Version 1.2.1

## Score

| | |
|---|---|
| Starting score | 110 |
| Deductions | -10 |
| **SPRS score** | **100** |
| Conditional threshold (88) | Met |

_Score assumes the 102 requirements not automatically assessed are implemented. Those require policy or personnel evidence and are flagged for manual review._

## Findings

| Requirement | Family | Status | Deduction | POA&M eligibility |
|---|---|---|---|---|
| 3.1.1 | Access Control | PASS | -0 | n/a |
| 3.1.22 | Access Control | FAIL | -1 | POA&M eligible |
| 3.3.1 | Audit and Accountability | PASS | -0 | n/a |
| 3.4.7 | Configuration Management | FAIL | -5 | MUST REMEDIATE before assessment |
| 3.5.3 | Identification and Authentication | PARTIAL | -3 | MUST REMEDIATE before assessment |
| 3.13.11 | System and Communications Protection | PASS | -0 | n/a |
| 3.13.16 | System and Communications Protection | FAIL | -1 | POA&M eligible |
| 3.14.6 | System and Information Integrity | PASS | -0 | n/a |

## Detail

### 3.1.1 - Access Control

> Limit system access to authorized users, processes acting for users, and devices

**Status:** PASS  
**Point weight:** 5  
**Deduction:** -0  
**POA&M:** n/a  
**Checked:** 2026-10-27T23:33:59.981005+00:00

**Evidence**

```json
{
  "stale_access_keys": []
}
```

### 3.1.22 - Access Control

> Control CUI posted or processed on publicly accessible systems

**Status:** FAIL  
**Point weight:** 1  
**Deduction:** -1  
**POA&M:** POA&M eligible  
**Checked:** 2026-10-27T23:33:59.981022+00:00

**Findings**

- 1 bucket without full public access block: cui-enclave-baseline-drawings (disabled: BlockPublicAcls, BlockPublicPolicy)

**Evidence**

```json
{
  "buckets_without_full_block": [
    "cui-enclave-baseline-drawings"
  ]
}
```

### 3.3.1 - Audit and Accountability

> Create and retain audit logs sufficient to monitor, analyze, investigate, and report unauthorized activity

**Status:** PASS  
**Point weight:** 5  
**Deduction:** -0  
**POA&M:** n/a  
**Checked:** 2026-10-27T23:33:59.981026+00:00

**Evidence**

```json
{}
```

### 3.4.7 - Configuration Management

> Restrict, disable, or prevent use of nonessential programs, functions, ports, protocols, and services

**Status:** FAIL  
**Point weight:** 5  
**Deduction:** -5  
**POA&M:** MUST REMEDIATE before assessment  
**Checked:** 2026-10-27T23:33:59.981028+00:00

**Findings**

- [HIGH] sg-0abc (cui-enclave-baseline-legacy) allows 22 from 0.0.0.0/0
- [HIGH] sg-0abc (cui-enclave-baseline-legacy) allows 3389 from 0.0.0.0/0

**Evidence**

```json
{}
```

### 3.5.3 - Identification and Authentication

> Use multifactor authentication for local and network access to privileged accounts and network access to non-privileged accounts

**Status:** PARTIAL  
**Point weight:** 5  
**Deduction:** -3  
**POA&M:** MUST REMEDIATE before assessment  
**Checked:** 2026-10-27T23:33:59.981030+00:00

**Findings**

- MFA enforced for the root account but missing for 1 console user

**Evidence**

```json
{}
```

### 3.13.11 - System and Communications Protection

> Employ FIPS validated cryptography when used to protect the confidentiality of CUI

**Status:** PASS  
**Point weight:** 5  
**Deduction:** -0  
**POA&M:** n/a  
**Checked:** 2026-10-27T23:33:59.981032+00:00

**Evidence**

```json
{}
```

### 3.13.16 - System and Communications Protection

> Protect the confidentiality of CUI at rest

**Status:** FAIL  
**Point weight:** 1  
**Deduction:** -1  
**POA&M:** POA&M eligible  
**Checked:** 2026-10-27T23:33:59.981034+00:00

**Findings**

- 1 unencrypted EBS volume: vol-0def

**Evidence**

```json
{}
```

### 3.14.6 - System and Information Integrity

> Monitor systems, including inbound and outbound traffic, to detect attacks and indicators of potential attacks

**Status:** PASS  
**Point weight:** 5  
**Deduction:** -0  
**POA&M:** n/a  
**Checked:** 2026-10-27T23:33:59.981035+00:00

**Evidence**

```json
{}
```
