# Known limitations

## What was and wasn't executed

**No AWS account or credentials were available** in the environment where
this project was built and validated. Everything that can run locally ran
and passed (see [testing.md](testing.md)), including a **full `terraform
apply` and `destroy` of all 182 resources against a local AWS emulator
(moto)** with live posture tests. The following cloud-side behaviour was
**not** verified against real AWS:

| Not executed against real AWS | Why it matters | How to verify |
| --- | --- | --- |
| `terraform plan/apply` in a real account | AWS API validation is stricter than moto (quotas, AZ availability, service-linked roles, KMS key-policy principal checks) | `make plan ENV=dev && make apply ENV=dev` |
| IAM policy *enforcement* and KMS conditions (`kms:ViaService`, encryption context) | moto stores policies but doesn't evaluate them, so a too-narrow condition (e.g. the Auto Scaling SLR `kms:ViaService = ec2`) could block instance launch | `make deploy-image` + `make cloud-test` |
| Real network paths (SG/NACL evaluation, endpoints, private DNS, S3 gateway prefix list) | Flows are verified statically and structurally, not with packets | `make cloud-test` (HTTPS + 401 + no port 80) and SSM Session Manager connectivity |
| Instance bootstrap (`dnf` via the S3 gateway endpoint, ECR pull, awslogs) | Depends on AWS-owned bucket names in the endpoint policy (`al2023-repos-<region>-de612dc2`, ECR starport layer bucket) | ALB target health after `make deploy-image` |
| WAF rule evaluation, anomaly detection, metric-filter matching, alarm firing | moto stores but doesn't evaluate them | Procedure in [monitoring.md](monitoring.md#verifying-the-pipeline-end-to-end-on-aws) |
| Performance Insights on `db.t4g.micro` | Engine/class support varies over time | Set `db_performance_insights = false` if the API rejects it |
| GitHub Actions execution | The workflows were linted (actionlint, checkov, semgrep) and every step runs locally via `make`, but they were never run on GitHub | Push to GitHub |

`terraform plan` *was* executed (against moto, with the real S3 backend
code path and native lock file).

## Emulator fidelity

* Re-planning against moto after apply reports in-place changes (S3 tags,
  KMS rotation period, RDS parameters, SG rule attributes). This is a moto
  read-back gap, not configuration drift. Idempotency must be confirmed on
  real AWS (`make plan` right after `make apply` should report no changes).
* The Terraform AWS provider talks to CloudWatch over Smithy RPCv2-CBOR,
  which moto 5.2 doesn't implement. `scripts/moto_cbor_shim.py` translates
  the calls for local runs only and is never deployed.
* `*.localhost` must resolve to loopback (true on Linux with systemd-resolved
  and in GitHub runners). On macOS, add `127.0.0.1 123456789012.localhost`
  to `/etc/hosts` for S3 Control calls.

## Design trade-offs (accepted for a dev / portfolio environment)

| Limitation | Production recommendation |
| --- | --- |
| The application connects with the RDS-managed **master** credential | Create a least-privilege `app` database role (IAM DB auth is already enabled) through a migration job, and remove master-secret access from the app role |
| API-token rotation is operator-driven (`make rotate-token`) | Secrets Manager rotation Lambda on a schedule |
| Single-AZ RDS, interface endpoints in one AZ | `db_multi_az = true`, `interface_endpoint_az_count = az_count` |
| Single region; no cross-region replication or AWS Backup vault lock | CRR for CloudTrail logs to a separate log-archive account; AWS Backup with vault lock |
| No AWS Config, Security Hub, IAM Access Analyzer, Organizations SCPs | Enable them (cost); add SCPs denying `cloudtrail:StopLogging`, leaving regions, root usage |
| Dev uses a self-signed certificate; the ALB doesn't validate target certificates | ACM certificate on a real domain (`certificate_arn`); target TLS still protects the hop inside the VPC |
| The container uses host networking so IMDSv2 keeps a hop limit of 1 | ECS/Fargate task roles would remove the instance-credential exposure entirely |
| CI can't run `terraform plan` against AWS (no plan role) | Add a read-only, OIDC-assumable plan role scoped to `pull_request` |
| Bootstrap state is a local file in `terraform/bootstrap` (git-ignored) | Migrate it into the bucket it created, or manage the backend from an org-level account |
| The `RDSOSMetrics` log group is created by RDS (account-wide name) without a CMK | Pre-create it per account with KMS + retention outside this stack |
| CloudWatch anomaly-detection bands need ~2 weeks of data | Tune thresholds after the learning period |
| Branch protection, environment reviewers and Dependabot alerts must be enabled in the GitHub UI | Codify with the GitHub Terraform provider |
| tfsec is deprecated upstream in favour of Trivy | Both run; drop tfsec once Trivy covers every check you rely on |
