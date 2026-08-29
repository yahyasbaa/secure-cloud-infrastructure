# Threat model

Methodology: **STRIDE** per element of the data-flow diagram, with a
qualitative risk rating (Likelihood × Impact, each Low/Medium/High). Every
control below points at the code that implements it, so the model can be
verified rather than taken on trust.

## 1. System overview

```
             (TB1) Internet
                  │ HTTPS 443 (TLS 1.2/1.3)
           ┌──────▼───────┐
           │  AWS WAFv2   │  managed rules + rate limit
           └──────┬───────┘
  ┌───────────────▼────────────────────────── VPC 10.20.0.0/16 ─────────┐
  │ public subnets  │ ALB (HTTPS only, drop invalid headers)             │
  │ (TB2)           │ HTTPS 8443 (re-encrypted)                          │
  │ app subnets     ▼                                                    │
  │ (no internet)  EC2 ASG ── container (non-root, read-only, no caps)   │
  │                  │  │ 443 → VPC endpoints: SSM, ECR, Secrets         │
  │                  │  │        Manager, CloudWatch Logs                │
  │                  │  └ 443 → S3 gateway endpoint (GetObject allow-list)│
  │ (TB3)            │ 5432 TLS (verify-full)                            │
  │ db subnets       ▼                                                   │
  │ (local route)  RDS PostgreSQL (encrypted, private, no egress)        │
  └──────────────────────────────────────────────────────────────────────┘
  (TB4) AWS control plane: IAM, KMS, CloudTrail, CloudWatch, Secrets Manager
  (TB5) GitHub Actions ──OIDC──► deployment role (ECR push, SSM tag, ASG refresh)
```

Trust boundaries: **TB1** internet → edge, **TB2** edge → private
application tier, **TB3** application → data tier, **TB4** workloads/people →
AWS APIs, **TB5** CI/CD → AWS account.

### Assets

| Asset | Sensitivity |
| --- | --- |
| Application data in PostgreSQL | Confidential |
| Database credentials (RDS-managed secret) | Secret |
| API bearer token | Secret |
| KMS keys (data, logs) | Critical: control of all encrypted data |
| CloudTrail / CloudWatch logs | Integrity-critical (forensics) |
| IAM roles and trust policies | Critical: privilege boundary |
| Terraform state | Confidential (resource metadata, dev TLS key) |
| CI/CD pipeline and container images | Integrity-critical (supply chain) |

### Actors

External attacker (anonymous internet), attacker holding stolen
credentials, compromised application (RCE in the container), malicious or
careless insider (developer/operator), compromised CI dependency.

## 2. STRIDE summary

| Element | S | T | R | I | D | E |
| --- | --- | --- | --- | --- | --- | --- |
| ALB / WAF (TB1) | T7 | T2 | T8 | T2 | T10 | — |
| Application host (TB2) | T1 | T6 | T8 | T4, T6 | T10 | T3, T6 |
| Database (TB3) | T1 | T5 | T8 | T4 | T10 | — |
| AWS APIs (TB4) | T1, T8 | T5, T9 | T9 | T4 | — | T3, T8 |
| CI/CD (TB5) | T1 | T11 | T9 | T1 | — | T3, T11 |

## 3. Threats

Ratings: L = Low, M = Medium, H = High. *Residual* is the rating after
controls.

### T1 – Credential compromise

| | |
| --- | --- |
| **Threat** | An attacker obtains AWS credentials (leaked access key, phished console password, stolen instance-role credentials via SSRF) or the API token, and uses them. *(Spoofing)* |
| **Likelihood** | High inherent → **Low** residual |
| **Impact** | High |
| **Preventive controls** | No IAM users or access keys exist (test `test_no_iam_users_or_access_keys`); CI uses short-lived OIDC credentials pinned to repo + environment (`deployment_role.tf`); human roles require MFA and fresh MFA (<1 h); instance credentials only via IMDSv2 with hop limit 1 (SSRF-resistant, `asg.tf`); secrets live in Secrets Manager encrypted with a CMK and are never in code, env files, user data or Terraform state (write-only secret, RDS-managed password); gitleaks on every commit and the full history; API token compared in constant time. |
| **Detective controls** | Alarms `console-signin-failures`, `console-signin-without-mfa`, `root-account-usage`, `unauthorized-api-calls`, `unauthorized-api-anomaly`, `unexpected-secret-access`, `app-auth-failures`, `db-auth-failures`; optional GuardDuty (credential exfiltration findings such as `InstanceCredentialExfiltration`). |
| **Response** | Revoke sessions for the role (IAM "Revoke active sessions" adds an `aws:TokenIssueTime` deny); rotate the API token (`make rotate-token`) and the RDS secret (`aws secretsmanager rotate-secret`); review CloudTrail for the principal's actions; terminate affected instances (the ASG replaces them from a clean image). |

### T2 – Public exposure

| | |
| --- | --- |
| **Threat** | A resource meant to be private (database, application host, bucket, secret) becomes reachable from the internet. *(Information disclosure)* |
| **Likelihood** | Medium inherent → **Low** residual |
| **Impact** | High |
| **Preventive controls** | Only the ALB is in public subnets and only port 443 is open; app and DB subnets have **no route** to an IGW or NAT; `publicly_accessible = false`; no public IPs (`map_public_ip_on_launch = false`, launch template `associate_public_ip_address = false`); all buckets have all four public-access blocks and `BucketOwnerEnforced`; secret resource policy denies other accounts; checkov/tfsec/trivy/terraform test/pytest all fail on any regression. |
| **Detective controls** | Live posture tests (`make cloud-test`) verify exposure on the real account; alarms `security-group-changes`, `nacl-changes`, `route-table-changes`, `network-gateway-changes`, `s3-bucket-policy-changes`; VPC flow logs capture REJECT/ACCEPT traffic. |
| **Response** | Revert the change with `terraform apply` (the code is the source of truth); review flow logs and S3/ALB access logs for access during the exposure window; rotate any credentials that might have been reachable. |

### T3 – Privilege escalation

| | |
| --- | --- |
| **Threat** | A principal with limited rights gains broader rights, e.g. by attaching policies, passing a powerful role to a new resource, or editing a trust policy. *(Elevation of privilege)* |
| **Likelihood** | Medium inherent → **Low** residual |
| **Impact** | High |
| **Preventive controls** | No runtime or CI role holds `iam:*`, `iam:PassRole`, policy-attach/put actions, `ssm:SendCommand`, `kms:CreateGrant` or `kms:PutKeyPolicy` (`docs/iam-model.md` § privilege-escalation review); no wildcard actions, `*` resources only for non-scopable actions (policy_sentry-verified tests); no managed admin policies; trust policies are narrow (OIDC `sub` exact match, MFA for humans, SourceArn/SourceAccount for services); infrastructure changes are not possible from CI. |
| **Detective controls** | Alarm `iam-policy-changes` (incl. `UpdateAssumeRolePolicy`); `unauthorized-api-calls` for probing; CloudTrail `LookupEvents` via the security-audit role. |
| **Response** | Detach or delete the injected policy and re-apply Terraform; revoke the principal's sessions; review CloudTrail for everything done with the elevated rights. |

### T4 – Data exfiltration

| | |
| --- | --- |
| **Threat** | Data is copied out of the environment: dumping the database through a compromised host, uploading to an attacker bucket, or copying snapshots/logs. *(Information disclosure)* |
| **Likelihood** | Medium inherent → **Low** residual |
| **Impact** | High |
| **Preventive controls** | App subnets have no internet egress (no NAT); the only egress is to VPC endpoints whose policies allow only this account's principals, and the S3 gateway endpoint allows only `s3:GetObject` on AWS-owned package/image buckets (no `PutObject` anywhere); DB security group has no egress; encryption at rest with CMKs whose use is limited by key policy and `kms:ViaService`; the auditor role is explicitly denied data-plane actions; ECR tags immutable. |
| **Detective controls** | VPC flow logs (unexpected destinations / volumes); `alb-request-anomaly` (scraping); `unexpected-secret-access`; CloudTrail records snapshot copy/share and KMS usage. |
| **Response** | Isolate the host (replace its security group or terminate it, letting the ASG recreate it); rotate DB and API credentials; disable the data key temporarily if needed (fails closed); determine scope from flow logs and DB connection logs. |

### T5 – Misconfigured security groups

| | |
| --- | --- |
| **Threat** | Someone opens a security group or NACL (e.g. 5432 or 22 to 0.0.0.0/0) through the console or a careless code change. *(Tampering → information disclosure)* |
| **Likelihood** | High inherent → **Low** residual |
| **Impact** | High |
| **Preventive controls** | Tier-to-tier rules reference security groups, not CIDRs; standalone rule resources only (no hidden inline rules); default SG locked; NACLs as a second, stateless layer (DB NACL only admits the app subnets on 5432); policy-as-code gates in CI: checkov, tfsec, trivy, `terraform test` (`network.tftest.hcl`) and pytest (`test_network.py`), so a PR that opens a port cannot merge. |
| **Detective controls** | Alarms `security-group-changes` and `nacl-changes`; live test `test_security_groups_are_restrictive` (verified to detect an injected 0.0.0.0/0 rule on 5432); `terraform plan` shows drift. |
| **Response** | Revoke the rule (`terraform apply` restores the declared state); check flow logs for connections that used the opening; find the change's author in CloudTrail. |

### T6 – Compromised application

| | |
| --- | --- |
| **Threat** | An attacker gains code execution in the container (vulnerable dependency, injection bug) and tries to persist, move laterally or reach the instance and AWS. *(Tampering, Elevation of privilege)* |
| **Likelihood** | Medium inherent → **Low/Medium** residual |
| **Impact** | Medium |
| **Preventive controls** | WAF managed rule groups (common, known-bad-inputs incl. Log4Shell, IP reputation, anonymous IPs) and rate limiting; input validation, parameterised SQL, size limits, no debug, generic errors; container runs as uid 10001 with a read-only root filesystem, `noexec` tmpfs, all capabilities dropped, `no-new-privileges`, memory/pid limits; dependencies hash-pinned and scanned (trivy, ECR scan-on-push; HIGH/CRITICAL blocks the build); semgrep SAST with project rules; instance role scoped to two secrets, one log group and one repository; the host can reach only the database and AWS endpoints. |
| **Detective controls** | `app-unhandled-errors`, `waf-blocked-spike`, `app-auth-failures`, `unexpected-secret-access` alarms; JSON security events in CloudWatch Logs; flow logs; optional GuardDuty runtime/EC2 findings. |
| **Response** | Terminate the instance (ASG replaces it from the known-good image); roll back to the previous immutable image tag (`make deploy-image TAG=<previous>`); rotate the DB secret and API token, which the compromised host could read; patch and redeploy. |

### T7 – Malicious insider

| | |
| --- | --- |
| **Threat** | A developer or operator with legitimate access abuses it: reads data, weakens controls, or erases evidence. *(Repudiation, Tampering)* |
| **Likelihood** | Low |
| **Impact** | High |
| **Preventive controls** | Operators get read-only roles (monitoring, security-audit) behind MFA; the audit role is explicitly denied data-plane access; infrastructure changes go through PR review and the CI gates (enable branch protection and GitHub environment reviewers); the CI role cannot change infrastructure; CloudTrail logs are encrypted with a separate logs key, protected by a bucket policy that denies object deletion, and include digest files for integrity validation. |
| **Detective controls** | Multi-region CloudTrail including read events; `cloudtrail-changes`, `kms-key-disable-or-deletion`, `s3-bucket-policy-changes`, `iam-policy-changes`, `unexpected-secret-access` alarms; real-time EventBridge rule `defense-evasion` (StopLogging, DeleteTrail, ScheduleKeyDeletion, DeleteFlowLogs, …). |
| **Response** | Disable the user's access at the identity provider; preserve evidence (CloudTrail S3 objects plus `aws cloudtrail validate-logs`); restore the declared configuration with Terraform; involve HR/legal. |

### T8 – Cloud API abuse

| | |
| --- | --- |
| **Threat** | Valid but misused credentials enumerate the account, create resources (crypto-mining, shadow infrastructure) or call APIs from unusual places. *(Spoofing, Elevation of privilege)* |
| **Likelihood** | Medium |
| **Impact** | Medium |
| **Preventive controls** | Least-privilege roles leave little to call; no role can create compute or IAM resources; VPC endpoint policies reject principals from other accounts; `allowed_account_ids` stops Terraform running against the wrong account. |
| **Detective controls** | `unauthorized-api-calls` (threshold) and `unauthorized-api-anomaly` (learned baseline); `root-account-usage`; `network-gateway-changes`; optional GuardDuty (unusual API patterns, crypto-mining); AWS Budgets alerts are recommended (see limitations). |
| **Response** | Revoke the principal's sessions and rotate; delete unauthorized resources; open an AWS support case if needed. |

### T9 – Tampering with audit logs

| | |
| --- | --- |
| **Threat** | An attacker disables CloudTrail, deletes or edits log files, or disables the logs key to blind the defenders. *(Repudiation, Tampering)* |
| **Likelihood** | Medium (typical first step after a compromise) |
| **Impact** | High |
| **Preventive controls** | Bucket policy denies `DeleteObject`/`DeleteObjectVersion` on CloudTrail logs; versioning; log-file validation (signed digests); separate logs CMK; logs also streamed to CloudWatch Logs (a second copy). |
| **Detective controls** | Real-time EventBridge `defense-evasion` rule plus the `cloudtrail-changes` and `kms-key-disable-or-deletion` alarms; live test `test_cloudtrail_enabled` checks `IsLogging`. |
| **Response** | Restart logging; validate log integrity (`aws cloudtrail validate-logs`); treat the event as an active incident. |

### T10 – Denial of service / resource exhaustion

| | |
| --- | --- |
| **Threat** | Floods or expensive requests exhaust the application, database or budget. *(Denial of service)* |
| **Likelihood** | Medium |
| **Impact** | Medium |
| **Preventive controls** | AWS Shield Standard (automatic on ALB); WAF per-IP rate limit; ALB desync mitigation and invalid-header dropping; request size and pagination limits; gunicorn timeouts; container memory/pid limits; Auto Scaling across two AZs. |
| **Detective controls** | `alb-request-anomaly`, `waf-blocked-spike`, `alb-5xx`, `unhealthy-hosts`, `db-cpu-high`, `db-free-storage-low`. |
| **Response** | Tighten WAF (lower rate limit, geo or IP blocks); scale out; consider Shield Advanced for production. |

### T11 – CI/CD and supply-chain compromise

| | |
| --- | --- |
| **Threat** | A malicious dependency, a hijacked GitHub Action or tampered tool runs in CI and pushes a backdoored image or steals credentials. *(Tampering, Elevation of privilege)* |
| **Likelihood** | Medium |
| **Impact** | High |
| **Preventive controls** | Every action pinned to a full commit SHA; all scanners and Terraform installed from pinned versions with **embedded SHA-256 verification**; Python dependencies hash-locked (`--require-hashes`); base image pinned by digest; read-only default `GITHUB_TOKEN`, `persist-credentials: false`, no `pull_request_target`; OIDC role usable only by the protected `dev` environment; images scanned before push and again by ECR; immutable tags; Dependabot updates through the full CI. |
| **Detective controls** | CI security gates on every PR; CloudTrail logs every action of the deployment role; ECR scan findings; SBOM generated per image (`reports/sbom-image.cdx.json`). |
| **Response** | Roll back to the previous image tag; revoke the deployment role's sessions; audit the workflow run logs; pin to a known-good revision of the affected dependency. |

## 4. Risk register (residual)

| ID | Threat | Likelihood | Impact | Residual risk |
| --- | --- | --- | --- | --- |
| T1 | Credential compromise | Low | High | Medium |
| T2 | Public exposure | Low | High | Medium |
| T3 | Privilege escalation | Low | High | Medium |
| T4 | Data exfiltration | Low | High | Medium |
| T5 | Misconfigured security groups | Low | High | Medium |
| T6 | Compromised application | Low/Medium | Medium | Medium |
| T7 | Malicious insider | Low | High | Medium |
| T8 | Cloud API abuse | Medium | Medium | Medium |
| T9 | Audit-log tampering | Low | High | Medium |
| T10 | Denial of service | Medium | Medium | Medium |
| T11 | Supply-chain compromise | Low | High | Medium |

Accepted residual risks and their mitigations for production are listed in
[known-limitations.md](known-limitations.md).
