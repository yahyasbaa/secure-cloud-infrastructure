# Logging and monitoring

## Log sources

| Source | Destination | Encryption | Retention | Purpose |
| --- | --- | --- | --- | --- |
| CloudTrail (multi-region, all management events, read + write, global services, log-file validation) | S3 `<name>-cloudtrail-*` **and** CloudWatch `/<name>/cloudtrail` | logs CMK | 365 days | API audit trail, alarm source |
| VPC Flow Logs (ALL traffic, 60 s aggregation) | CloudWatch `/<name>/vpc-flow-logs` | logs CMK | 365 days | network forensics, exfiltration analysis |
| Application (JSON, one event per line) | CloudWatch `/<name>/app` (docker `awslogs` driver) | logs CMK | 365 days | security events (`auth_failure`, …), access log |
| PostgreSQL (connections, disconnections, auth failures, DDL, slow queries) | CloudWatch `/aws/rds/instance/<name>-db/postgresql` | logs CMK | 365 days | database authentication alarms |
| RDS upgrade log | CloudWatch `/aws/rds/instance/<name>-db/upgrade` | logs CMK | 365 days | change tracking |
| WAF (Authorization header redacted) | CloudWatch `aws-waf-logs-<name>` | logs CMK | 365 days | blocked attacks |
| ALB access + connection logs | S3 `<name>-alb-logs-*` | SSE-S3 (ELB limitation) | 365 days | request forensics, TLS/client details |
| S3 server access logs | S3 `<name>-s3-access-logs-*` | SSE-S3 (S3 limitation) | 365 days | who read the CloudTrail/ALB logs |
| RDS Enhanced Monitoring (60 s) and Performance Insights | `RDSOSMetrics` / PI | PI: data CMK | 7 days (PI free tier) | performance and abuse detection |

### Application security events

The app emits structured JSON (`app/sci_app/logging_setup.py`). Metric
filters match on the stable `event` field:

| `event` | Meaning |
| --- | --- |
| `auth_failure` | Missing or invalid bearer token (`source_ip`, `path`, `reason`; the presented token is never logged) |
| `request_too_large` | Body over the configured limit |
| `unhandled_error` | Server error (only the exception type is logged) |
| `secret_lookup_failed` | Secrets Manager unreachable; the API fails closed (503) |
| `http_access` | Access log line from gunicorn |

## Alarms

All alarms publish to the KMS-encrypted SNS topic `<name>-security-alarms`
(subscribe an e-mail with `alarm_email`, or attach chat/incident tooling).
Log-based alarms evaluate a 5-minute sum; missing data counts as "not
breaching". CloudTrail patterns follow the CIS AWS Foundations Benchmark
monitoring controls.

### Authentication and access

| Alarm | Fires when | Why it matters | First response |
| --- | --- | --- | --- |
| `app-auth-failures` | ≥ 10 rejected API tokens in 5 min | Brute force or credential stuffing against the API (repeated authentication failures) | Check `source_ip` in `/<name>/app`; add a WAF IP block; rotate the token if a valid one may be exposed |
| `console-signin-failures` | ≥ 3 failed console sign-ins in 5 min | Password guessing against IAM users / SSO | Identify the user in CloudTrail; lock the account; enforce MFA |
| `db-auth-failures` | ≥ 5 PostgreSQL `password authentication failed` / `no pg_hba.conf entry` in 5 min | Password guessing from inside the VPC means a host is already compromised, or a stale secret is in use | Find the client IP in the DB log; isolate the host; rotate the DB secret |
| `console-signin-without-mfa` | Any successful IAM-user console login without MFA | MFA bypass / weak account | Enforce MFA; review the session's actions |
| `root-account-usage` | Any root-user API or console activity | Root should never be used day to day | Verify with the account owner; rotate root credentials; review all actions |
| `unauthorized-api-calls` | ≥ 5 `AccessDenied` / `UnauthorizedOperation` in 5 min | Stolen credentials probing their permissions | Identify the principal; revoke sessions if unexpected |
| `unexpected-secret-access` | `GetSecretValue` by any principal other than the application role (AWS services excluded) | Unusual access pattern: insider or stolen credential reading secrets | Identify the caller; rotate the secret that was read |

### Unusual access patterns (anomaly detection)

| Alarm | Fires when | Why it matters | First response |
| --- | --- | --- | --- |
| `alb-request-anomaly` | ALB request count leaves the learned band (3 standard deviations, 3 × 5 min) | Scraping, scanning, credential stuffing at volume, L7 DDoS | Inspect WAF sampled requests and ALB logs; tighten the rate limit |
| `unauthorized-api-anomaly` | Denied API calls leave the learned band (2 standard deviations, 2 × 5 min) | Slow reconnaissance that stays under fixed thresholds | Same as `unauthorized-api-calls` |
| `waf-blocked-spike` | WAF blocks ≥ 100 requests in 5 min | Active attack or scanning campaign | Review the matching rules in WAF logs; consider blocking the source |

### Configuration changes (possible defence evasion or exposure)

| Alarm | Fires on | Why it matters |
| --- | --- | --- |
| `security-group-changes` | Authorize/Revoke ingress/egress, Create/Delete SG, ModifySecurityGroupRules | A private tier could be exposed |
| `nacl-changes` | Any NACL or NACL entry change | Network isolation weakened |
| `iam-policy-changes` | Any IAM policy create/delete/version/attach/detach, inline put/delete, trust-policy update | Privilege escalation |
| `route-table-changes` | Route/route-table create, replace, delete, disassociate | A private subnet could gain an internet path |
| `network-gateway-changes` | IGW/NAT/customer gateway changes | New ingress/egress path |
| `vpc-changes` | VPC create/delete/attribute changes, peering | Network boundary changes |
| `cloudtrail-changes` | Create/Update/Delete trail, Start/StopLogging, PutEventSelectors | Attacker blinding the audit trail |
| `kms-key-disable-or-deletion` | DisableKey, ScheduleKeyDeletion, PutKeyPolicy | Ransom or denial of access to encrypted data |
| `s3-bucket-policy-changes` | Bucket policy/ACL/CORS/lifecycle/replication/public-access-block changes | Data exposure or exfiltration via replication |

First response for all of the above: confirm the change against an approved
PR or change ticket. If it isn't one, revert it with `terraform apply` and
investigate the principal in CloudTrail.

### Service health

| Alarm | Fires when | Why it matters |
| --- | --- | --- |
| `alb-5xx` | ≥ 10 ELB 5xx responses in 5 min | Outage, or exploitation causing crashes |
| `unhealthy-hosts` | ≥ 1 unhealthy target for 10 min | Failed deploy or compromised/crashed host |
| `db-cpu-high` | DB CPU > 80 % for 15 min | Load, runaway or malicious queries |
| `db-free-storage-low` | < 2 GiB free storage | Exhaustion attack or growth; RDS stops accepting writes at 0 |
| `app-unhandled-errors` | ≥ 5 unhandled errors in 5 min | Exploitation attempts or bugs |

### Real-time event rules (EventBridge → SNS)

| Rule | Matches | Latency |
| --- | --- | --- |
| `defense-evasion` | `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, `ScheduleKeyDeletion`, `DisableKey`, `DeleteDetector`, `DisassociateFromMasterAccount`, `DeleteFlowLogs` | seconds |
| `guardduty-high-severity` (when `enable_guardduty = true`) | GuardDuty findings with severity ≥ 7 | ~minutes |

## Verifying the pipeline end-to-end (on AWS)

```bash
# 1. Generate app auth failures (expect the app-auth-failures alarm in ~5 min)
for i in $(seq 1 15); do curl -sk -o /dev/null "https://$(terraform -chdir=terraform output -raw alb_dns_name)/api/notes" -H 'Authorization: Bearer wrong'; done

# 2. Trigger the security-group-changes alarm with a harmless no-op change
SG=$(aws ec2 describe-security-groups --filters Name=group-name,Values=sci-dev-app --query 'SecurityGroups[0].GroupId' --output text)
aws ec2 create-tags --resources "$SG" --tags Key=alarm-test,Value=1   # not an SG rule change: no alarm
aws ec2 authorize-security-group-egress --group-id "$SG" --ip-permissions 'IpProtocol=tcp,FromPort=9,ToPort=9,IpRanges=[{CidrIp=10.20.255.255/32}]'
aws ec2 revoke-security-group-egress   --group-id "$SG" --ip-permissions 'IpProtocol=tcp,FromPort=9,ToPort=9,IpRanges=[{CidrIp=10.20.255.255/32}]'

# 3. Watch alarm state
aws cloudwatch describe-alarms --alarm-name-prefix sci-dev- --state-value ALARM --query 'MetricAlarms[].AlarmName'
```
