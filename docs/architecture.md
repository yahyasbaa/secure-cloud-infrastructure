# Architecture

```
                                   Internet
                                       │  HTTPS :443 only (TLS 1.2 / 1.3)
                                ┌──────▼──────┐
                                │   AWS WAF   │ common + bad-inputs + IP reputation
                                │  (regional) │ + anonymous-IP + per-IP rate limit
                                └──────┬──────┘
 ┌─────────────────────────────────────┼─────────────────────── VPC 10.20.0.0/16 ─┐
 │  Public subnets (AZ a / b)          │                                          │
 │   10.20.0.0/24  10.20.1.0/24   ┌────▼──────────────────┐                       │
 │                                │ Application Load      │ access + connection   │
 │                                │ Balancer (HTTPS only) │ logs → S3             │
 │                                └────┬──────────────────┘                       │
 │                                     │ HTTPS :8443 (re-encrypted)               │
 │  Private app subnets (no internet route, no NAT)                               │
 │   10.20.10.0/24 10.20.11.0/24  ┌────▼──────────────────┐    ┌───────────────┐  │
 │                                │ EC2 Auto Scaling group │──▶│ VPC endpoints │──┼─▶ SSM, ECR, Secrets
 │                                │ AL2023, IMDSv2, no SSH │443│ (interface)   │  │   Manager, CloudWatch
 │                                │ container: non-root,   │   └───────────────┘  │   Logs
 │                                │ read-only, no caps     │──▶ S3 gateway endpoint ─▶ OS packages,
 │                                └────┬───────────────────┘   (GetObject allow-list)  image layers
 │                                     │ PostgreSQL :5432, TLS verify-full        │
 │  Private DB subnets (local route only)                                         │
 │   10.20.20.0/24 10.20.21.0/24  ┌────▼──────────────────┐                       │
 │                                │ RDS PostgreSQL 17     │ encrypted (CMK),      │
 │                                │ not public, no egress │ IAM auth, force_ssl   │
 │                                └───────────────────────┘                       │
 │  VPC Flow Logs (ALL) ──────────────────────────────────────────▶ CloudWatch Logs│
 └────────────────────────────────────────────────────────────────────────────────┘

 Account-level:  CloudTrail (multi-region, validated, KMS) ─▶ S3 + CloudWatch Logs ─▶ metric filters ─▶ alarms ─▶ SNS (KMS)
                 KMS: data key │ logs key        Secrets Manager: API token │ RDS-managed DB secret
                 IAM: app │ deployment (GitHub OIDC) │ monitoring (MFA) │ security-audit (MFA)
                 EventBridge: defence-evasion events, GuardDuty high-severity findings (optional)
```

## Request path

1. The client connects to the ALB over HTTPS. WAF evaluates the managed rule
   groups and the rate limit first.
2. The ALB (TLS policy `ELBSecurityPolicy-TLS13-1-2-Res-2021-06`) forwards to
   a healthy target over HTTPS on port 8443. The only listener is 443.
3. Gunicorn (TLS ≥ 1.2) serves the Flask app as uid 10001 in a read-only
   container. API routes require a bearer token, compared in constant time
   against the `AWSCURRENT`/`AWSPREVIOUS` values from Secrets Manager.
4. The app connects to PostgreSQL with TLS `verify-full`, using the
   RDS-managed credential fetched from Secrets Manager through the VPC
   endpoint.

## Deployment path

1. A PR runs the CI security pipeline (fmt, validate, terraform test, tflint,
   checkov, tfsec, trivy, gitleaks, semgrep, actionlint, unit + security
   tests, local deployment to a moto emulator with posture tests, container
   build + scan + SBOM).
2. Merging to `main` runs the `deploy` workflow: CI again, then the protected
   `dev` environment job assumes the deployment role via **OIDC** (no stored
   keys). It builds the image, gates it on a Trivy scan, pushes to ECR
   (immutable tags, scan-on-push, second gate on ECR findings), updates the
   image-tag SSM parameter and starts a rolling instance refresh (≥ 50 %
   healthy).
3. New instances boot from AL2023, install Docker from the AL2023 repositories
   through the S3 gateway endpoint, pull the image through the ECR endpoints
   and run it with a hardened `docker run` profile, logging to CloudWatch.

Infrastructure changes (`terraform apply`) are made by an administrator
from a reviewed plan, not by the pipeline. See [deployment.md](deployment.md).

## Terraform layout

| Path | Contents |
| --- | --- |
| `terraform/{providers,variables,main,outputs}.tf` | Root stack: wires the modules; S3 backend with native locking; `allowed_account_ids` guard |
| `terraform/modules/security` | KMS keys (data, logs), dedicated Auto Scaling service-linked role, API-token secret (write-only) |
| `terraform/modules/network` | VPC, 3-tier subnets, route tables, NACLs, security groups, VPC endpoints + policies, flow logs |
| `terraform/modules/logging` | CloudTrail, log groups, S3 log buckets (CloudTrail, ALB, access logs) |
| `terraform/modules/database` | RDS PostgreSQL, parameter group, log groups, enhanced-monitoring role |
| `terraform/modules/iam` | Application, deployment (GitHub OIDC), monitoring and security-audit roles |
| `terraform/modules/compute` | ECR, ALB, listener, target group, WAF, launch template, Auto Scaling group |
| `terraform/modules/monitoring` | Metric filters, alarms, anomaly detection, SNS, EventBridge rules, GuardDuty |
| `terraform/bootstrap` | One-time state backend (KMS-encrypted, versioned, access-logged S3) |
| `terraform/environments/{dev,local}` | Per-environment variables and backend configuration |
| `terraform/tests` | `terraform test` suites with a mocked AWS provider |

Module dependency order: `security → logging → network → database → iam → compute → monitoring`.
