# Secure Cloud Infrastructure

A reproducible, security-first **three-tier AWS architecture** built with
Terraform: an internet-facing load balancer, private application hosts with
no internet route, and a private encrypted PostgreSQL database. It comes
with least-privilege IAM, KMS encryption, Secrets Manager, CloudTrail and
CloudWatch detection, policy-as-code scanning, automated security tests and
a GitHub Actions pipeline that authenticates to AWS through OIDC.

You can validate everything **without an AWS account**: `make all` runs all
static checks and scanners, deploys the complete stack (182 resources) into
a local AWS emulator, runs live security posture tests against it, destroys
it, and smoke-tests the hardened container over HTTPS.

```
Internet ──HTTPS 443──▶ WAF ─▶ ALB (public subnets, HTTPS only)
                                 │ HTTPS 8443
                                 ▼
                 EC2 Auto Scaling (private app subnets, no internet route)
                   │ 443 → VPC endpoints (SSM, ECR, Secrets Manager, Logs) + S3 gateway
                   │ 5432 TLS verify-full
                   ▼
                 RDS PostgreSQL (private DB subnets, encrypted, no egress)

CloudTrail · VPC Flow Logs · app/DB/WAF logs → CloudWatch (KMS) → 24 alarms → SNS
```

## Contents

| # | Deliverable | Where |
| --- | --- | --- |
| 1 | Architecture | [docs/architecture.md](docs/architecture.md) |
| 2 | Terraform implementation | [`terraform/`](terraform): root stack, 7 modules, bootstrap, environments, `terraform test` suites |
| 3 | IAM model | [docs/iam-model.md](docs/iam-model.md) |
| 4 | Network security model | [docs/network-security.md](docs/network-security.md) |
| 5 | Encryption model | [docs/encryption.md](docs/encryption.md) |
| 6 | Logging / monitoring (every alarm documented) | [docs/monitoring.md](docs/monitoring.md) |
| 7 | Threat model (STRIDE) | [docs/threat-model.md](docs/threat-model.md) |
| 8 | Security scans | [`scripts/security-scan.sh`](scripts/security-scan.sh), [`security/`](security), [suppression register](security/suppressions.md) |
| 9 | Automated tests | [`tests/`](tests), [`terraform/tests/`](terraform/tests), [docs/testing.md](docs/testing.md) |
| 10 | CI/CD | [`.github/workflows/`](.github/workflows), [docs/cicd.md](docs/cicd.md) |
| 11 | Deployment commands | [docs/deployment.md](docs/deployment.md#2-deploy-to-aws-dev) |
| 12 | Cleanup commands | [docs/deployment.md](docs/deployment.md#3-cleanup-complete-teardown) |
| 13 | Test results | [docs/testing.md](docs/testing.md#final-verification-run) |
| 14 | Known limitations | [docs/known-limitations.md](docs/known-limitations.md) |
| — | Cost estimate | [docs/cost.md](docs/cost.md) |
| — | Vulnerability reporting | [SECURITY.md](SECURITY.md) |

## Quick start

Requirements: Linux or macOS, `bash`, `make`, `python3` with `venv`, `curl`,
`git`, Docker. Every other tool is installed locally at a pinned version with
SHA-256 verification.

```bash
make tools        # Terraform, checkov, tfsec, trivy, gitleaks, semgrep, tflint, actionlint, pytest, moto → ./.tools
make all          # the complete local pipeline (~10 min)
```

Or run the pieces:

```bash
make validate       # terraform fmt -check + validate + tflint, unit tests, security config tests, all scanners incl. secrets
make security-test  # pytest security tests + terraform test (mocked provider)
make security-scan  # checkov, tfsec, trivy (IaC, deps, image), gitleaks, semgrep, actionlint → reports/
make local-stack    # LOCAL MODE: plan/apply the full stack to a moto AWS emulator, posture tests, destroy
make smoke          # build the image, run it with PostgreSQL, HTTPS smoke tests
make help           # everything else
```

### Deploy to AWS

```bash
make bootstrap                      # one-time: encrypted, versioned, locked state bucket
$EDITOR terraform/environments/dev/terraform.tfvars   # github_repository, allowed_account_ids, ...
make init plan ENV=dev              # review the plan
make apply ENV=dev
make deploy-image ENV=dev           # build → scan → push → roll out
make cloud-test ENV=dev             # live posture tests against the real account
```

### Clean up

```bash
make destroy ENV=dev CONFIRM=dev                 # lifts deletion guards, then destroys everything
make destroy-bootstrap CONFIRM=destroy-state     # optional: remove the state backend
```

Full runbook: [docs/deployment.md](docs/deployment.md). Approximate cost
while running: about $0.15/hour ([docs/cost.md](docs/cost.md)).

## Security controls at a glance

| Domain | Controls |
| --- | --- |
| **Network** | 3 tiers × 2 AZs; only the ALB is public (443 only, no HTTP listener); app and DB subnets have no internet route and no NAT; SG-to-SG rules (ALB→app:8443, app→DB:5432); DB and endpoint SGs have no egress; NACLs as a second layer; locked default SG; VPC endpoints whose policies only allow this account; S3 gateway endpoint limited to `GetObject` on AWS package buckets (exfiltration control); WAF with managed rules + rate limiting; flow logs |
| **IAM** | 4 purpose-built roles (app, deployment, monitoring, security-audit) + scoped service roles; no managed policies, no wildcard actions, `*` resources only where AWS has no resource-level support (checked against the IAM database); GitHub OIDC pinned to repo + environment; MFA for humans; auditor explicitly denied data-plane access |
| **Encryption** | Separate CMKs for data and logs with rotation and explicit key policies (no `kms:*`); RDS, EBS, ECR, Secrets Manager, Performance Insights, CloudTrail, CloudWatch Logs, SNS encrypted; TLS 1.2+/1.3 at the edge, re-encrypted ALB→app, `verify-full` TLS to PostgreSQL with `rds.force_ssl` |
| **Secrets** | RDS-managed master password; API token generated ephemerally and written **write-only** (never in state, verified by a live test); app reads Secrets Manager at runtime via `kms:ViaService`; `.env.example` placeholders only; gitleaks on tree and history |
| **Compute / container** | IMDSv2 (hop limit 1), no SSH or key pairs (SSM Session Manager), encrypted EBS; non-root, read-only, capability-less container; digest-pinned base image; hash-locked dependencies; image scanning before push and in ECR |
| **Detection** | Multi-region validated CloudTrail; 17 CIS-style metric-filter alarms (unauthorized calls, auth failures, changes to security groups, NACLs, IAM, routes, KMS keys and bucket policies, root use, unexpected secret access); anomaly detection on traffic and denied calls; app/DB auth-failure alarms; real-time defence-evasion rule; optional GuardDuty |
| **Pipeline** | PR gates: fmt, validate, terraform test, tflint, checkov, tfsec, trivy, gitleaks, semgrep, actionlint, unit + security tests, local cloud deployment, container scan + SBOM; SHA-pinned actions; read-only token; OIDC deploy behind a protected environment |

## Repository layout

```
.
├── README.md  SECURITY.md  Makefile  .env.example  .gitignore  pytest.ini
├── app/                 Flask API (sci_app/), gunicorn TLS config, hash-locked requirements
├── docker/              Hardened multi-stage Dockerfile, docker-compose for local runs
├── terraform/
│   ├── providers.tf variables.tf main.tf outputs.tf   root stack
│   ├── modules/         security · network · logging · database · iam · compute · monitoring
│   ├── environments/    dev (real AWS) · local (moto emulator)
│   ├── bootstrap/       remote-state backend
│   └── tests/           terraform test suites + offline provider mocks
├── tests/
│   ├── unit/            application tests
│   └── security/        static/ (HCL, IAM, network, secrets, CI, docs) · live/ (deployed posture)
├── scripts/             install-tools, security-scan, local-stack, deploy-image, cloud-test, ...
├── security/            checkov / gitleaks / semgrep configuration, suppression register
├── docs/                architecture, IAM, network, encryption, monitoring, threat model, CI/CD, ...
└── .github/             ci.yml, deploy.yml, dependabot.yml
```

## Test results

The results of the last full verification run are recorded in
[docs/testing.md](docs/testing.md#final-verification-run).
