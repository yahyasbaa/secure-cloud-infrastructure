# Encryption model

No encryption key is ever hard-coded or generated outside AWS KMS. Two
customer-managed keys (CMKs) separate **data** from **audit**: a credential
able to decrypt application data cannot read or tamper with the audit trail,
and vice versa. Both keys rotate automatically every 365 days and keep the
maximum 30-day deletion window (the `kms-key-disable-or-deletion` alarm and
the `defense-evasion` real-time rule fire on any attempt to disable or
delete them).

## At rest

| What | Key | Who can use the key for it | Why this way |
| --- | --- | --- | --- |
| RDS storage, automated backups, snapshots | `alias/<name>-data` | RDS on behalf of callers authorised by IAM | Customer control over the data key; access is auditable in CloudTrail |
| RDS master credentials (Secrets Manager, RDS-managed) | `alias/<name>-data` | Application role, via `kms:Decrypt` **only with `kms:ViaService = secretsmanager`** | The password is generated and rotated by RDS and never appears in code or Terraform state |
| Application API token (Secrets Manager) | `alias/<name>-data` | Application role (same ViaService restriction) | Written through a **write-only** attribute from an **ephemeral** value: never in plan or state |
| Performance Insights | `alias/<name>-data` | RDS | Query samples can contain data |
| EBS root volumes | `alias/<name>-data` | Auto Scaling service-linked role, only via EC2 (`kms:ViaService = ec2`) | Host disks may hold cached data/logs |
| ECR images | `alias/<name>-data` | ECR on behalf of push/pull principals | Image layers |
| CloudTrail log files (S3) | `alias/<name>-logs` | `cloudtrail.amazonaws.com`, only for this trail (`aws:SourceArn` + encryption context) | Integrity and confidentiality of the audit trail |
| All CloudWatch log groups (app, flow logs, CloudTrail, RDS, WAF) | `alias/<name>-logs` | `logs.<region>.amazonaws.com`, only for this stack's log-group ARNs (encryption-context condition) | Logs contain IPs, query text and security events |
| SNS alarm topic | `alias/<name>-logs` | CloudWatch and EventBridge of this account | Alarm payloads describe security events |
| ALB logs, S3 access logs | SSE-S3 (AES-256) | S3 | ELB log delivery and S3 server access logging **do not support SSE-KMS targets** (documented AWS limitation) |
| Terraform state (bootstrap bucket) | `alias/<project>-tfstate` | Administrators via IAM; the bucket policy rejects state written with any other key | State contains resource metadata (and, in dev, the self-signed TLS key) |

Key policies (`terraform/modules/security/kms.tf`) contain **no `kms:*`**:
the account root receives explicit administration and usage action lists,
which delegates authorisation to IAM policies. Each IAM role then gets only
what it needs (see [iam-model.md](iam-model.md)). No runtime or CI role can
change a key policy, create grants, disable or delete a key.

## In transit

| Hop | Protection |
| --- | --- |
| Client → ALB | HTTPS only; **no port-80 listener exists**. Policy `ELBSecurityPolicy-TLS13-1-2-Res-2021-06` (TLS 1.3 and TLS 1.2 with forward-secret AEAD ciphers only); HSTS header from the app |
| ALB → application | Re-encrypted: HTTPS to the target on 8443 (TLS ≥ 1.2, per-boot self-signed key generated in memory into a 0600 tmpfs file) |
| Application → PostgreSQL | TLS required server-side (`rds.force_ssl = 1`); the client uses `sslmode=verify-full` against the RDS CA bundle, pinned by SHA-256 in the image |
| Application → AWS APIs | HTTPS to VPC interface endpoints (private DNS) and the S3 gateway endpoint |
| Buckets / SNS | Policies deny any request with `aws:SecureTransport = false` |

## Certificates

* **Production:** set `certificate_arn` to an ACM certificate for a domain
  you own (ACM renews it automatically).
* **Dev without a domain:** Terraform generates a self-signed ECDSA P-256
  certificate (90 days) and imports it into ACM, so the listener stays
  HTTPS-only. Its private key is stored in Terraform state, which is
  KMS-encrypted and access-logged. That is acceptable for a disposable dev
  environment only.

## Secrets lifecycle

| Secret | Created by | Rotation |
| --- | --- | --- |
| DB master password | RDS (`manage_master_user_password`) | Automatic, managed by RDS (7-day default); the app re-reads the secret on authentication failure |
| API token | Terraform ephemeral `random_password` → write-only `secret_string_wo` | `make rotate-token ENV=dev` (Secrets-Manager-generated value via a 0600 temp file), or bump `app_token_version`. The app accepts `AWSCURRENT` and `AWSPREVIOUS`, so clients get a grace period |
| Local development secrets | `make local-env` writes `.env` (0600, git-ignored) with random values | Delete `.env` and regenerate |

`.env.example` contains placeholders only (enforced by
`tests/security/static/test_secrets.py`), and gitleaks scans the working tree
and the full git history in CI.
