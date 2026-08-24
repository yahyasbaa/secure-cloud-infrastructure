# Scanner suppression register

Every suppressed scanner finding is a deliberate, reviewed risk decision.
Rules:

1. Suppressions are **inline**, next to the exact resource, with the reason
   on the same line. There are no global skip lists; `security/checkov.yaml`
   is checked by a test to make sure there never are.
2. Each suppression must be registered here. `tests/security/static/test_suppressions.py`
   fails the build for an unregistered or unexplained suppression.
3. A suppression is never used to make a test pass when the control could be
   implemented. Most entries below are either **false positives** (the
   scanner can't see the control) or **AWS platform limitations**.

## Checkov

| ID | Where | Classification | Justification | Compensating control |
| --- | --- | --- | --- | --- |
| `CKV_AWS_111`, `CKV_AWS_356`, `CKV_AWS_109` | KMS key policies (`modules/security/kms.tf`, `bootstrap/main.tf`) | False positive | These checks target identity policies. In a **key policy** `Resource "*"` means "this key" and is mandatory; admin actions are scoped to that one key | Explicit action lists (no `kms:*`); service statements carry encryption-context / SourceArn / ViaService conditions; `test_kms_key_policies_have_no_wildcard_principals` |
| `CKV2_AWS_5` | `alb`, `app`, `db` security groups (`modules/network/security_groups.tf`) | False positive | The groups are attached in other modules through module outputs, which checkov's graph does not follow | `terraform test` and live tests prove the attachments; the `endpoints` SG (attached in-module) passes |
| `CKV_AWS_260` | `alb_https` ingress rule | False positive | The check is about port 80; the rule opens port 443 on the internet-facing ALB, which is its purpose | WAF, HTTPS only, `alb_ingress_cidrs` lets you restrict sources |
| `CKV2_AWS_20` | ALB (`modules/compute/alb.tf`) | False positive | There is no HTTP listener to redirect; plaintext HTTP isn't served at all | `test_alb_is_https_only`, `cloud-test.sh` checks that port 80 doesn't answer |
| `CKV_AWS_157` | RDS instance | Accepted (cost) | Multi-AZ doubles cost and is an availability control, not a confidentiality one; it's exposed as `db_multi_az` | Automated backups (7 days), deletion protection, final snapshot; enable `db_multi_az` for production |
| `CKV_AWS_145` | ALB-log and S3-access-log buckets | AWS limitation | ELB log delivery and S3 server access logging only support SSE-S3 destination buckets | SSE-S3 encryption, TLS-only policy, public access blocked, versioning |
| `CKV_AWS_18` | S3 access-log buckets (`access_logs`, bootstrap `state_logs`) | Design | It *is* the access-log target; logging it to itself would recurse | Bucket policy allows only the S3 logging service; all public access blocked |
| `CKV_AWS_144` | All log/state buckets | Accepted (cost) | Cross-region replication doubles storage cost for a single-region dev environment | Versioning, deny-delete policy on CloudTrail logs, CloudTrail logs duplicated in CloudWatch Logs; documented production enhancement |
| `CKV2_AWS_62` | All log/state buckets | Not applicable | Event notifications add nothing for log storage | Security events are alarmed from CloudTrail metric filters |
| `CKV_AWS_252` | CloudTrail trail | Design | Per-log-file SNS notifications are noise | CloudWatch Logs integration with 17 metric-filter alarms + real-time EventBridge rule |
| `CKV2_AWS_3` | GuardDuty detector | Not applicable | Organisation-wide configuration needs an AWS Organizations delegated admin; this is a single-account deployment | Detector enabled per account/region when `enable_guardduty = true` |
| `CKV2_AWS_57` | Application API-token secret | Accepted | Automatic rotation needs a rotation Lambda plus extra VPC endpoints and cost | Rotation by `make rotate-token` (Secrets-Manager-generated value) or `app_token_version`; app accepts current + previous for zero-downtime rotation; `unexpected-secret-access` alarm |
| `CKV2_AWS_34` | SSM parameter holding the image tag | Not applicable | Holds a public container image tag, not sensitive data. A `String` keeps the deployment role free of KMS permissions | Parameter writable only by the deployment role |
| `CKV_DOCKER_4` | `docker/Dockerfile` (RDS CA bundle) | False positive | `ADD --checksum=sha256:…` is the only instruction that fetches a remote file *with* integrity verification; `COPY` can't fetch | The build fails if the downloaded bytes don't match the pinned SHA-256 |

## tfsec / Trivy (same rule set)

| ID | Where | Classification | Justification | Compensating control |
| --- | --- | --- | --- | --- |
| `aws-ec2-no-public-ingress-sgr` / `AVD-AWS-0107` | `alb_https` SG rule | Design | The ALB is the public HTTPS entry point | Port 443 only, WAF, rate limiting, `alb_ingress_cidrs` |
| `aws-ec2-no-public-ingress-acl` / `AVD-AWS-0105` | Public NACL 443 rule; app NACL 32768–65535 rule | Design | (1) HTTPS entry point; (2) return traffic from S3's public IP space through the gateway endpoint. App subnets have no internet route, so the rule can't admit new connections | Security groups (stateful) allow no inbound internet traffic to the app tier |
| `aws-elb-alb-not-public` | ALB `internal = false` | Design | Internet-facing by design | WAF, TLS policy, SG |
| `aws-s3-encryption-customer-key` | ALB-log and access-log bucket encryption | AWS limitation | See `CKV_AWS_145` | SSE-S3 |
| `aws-s3-enable-bucket-logging` | Access-log target buckets | Design | See `CKV_AWS_18` | — |
| `aws-iam-no-policy-wildcards` | Flow-log delivery policy | Inherent | `log-stream:*` under one specific log group: the service creates one stream per ENI with generated names | Scoped to a single log group ARN |

## Gitleaks

| Path | Classification | Justification | Compensating control |
| --- | --- | --- | --- |
| `.env` | Design | Locally generated random secrets for docker compose (`make local-env`), git-ignored | `scripts/security-scan.sh` fails if `.env` is ever tracked by git; history scan in CI; `test_env_files_are_ignored` |

## Semgrep

No suppressions.
