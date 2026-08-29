# Testing strategy and results

## Test layers

| Layer | Tool | Location | Needs AWS? | Runs in |
| --- | --- | --- | --- | --- |
| Formatting | `terraform fmt -check` | all Terraform | no | `make fmt-check`, CI |
| Configuration validity | `terraform validate` | root stack + bootstrap | no | `make tf-validate`, CI |
| Module security assertions | `terraform test` with a **mocked AWS provider** | `terraform/tests/*.tftest.hcl` | no | `make tf-test`, CI |
| Lint | tflint + AWS ruleset | all Terraform | no | `make tflint`, CI |
| Static security tests | pytest + python-hcl2 + policy_sentry | `tests/security/static` | no | `make security-test`, CI |
| Application unit tests | pytest + Flask test client | `tests/unit` | no | `make unit-test`, CI |
| IaC scanners | checkov, tfsec, trivy config | `terraform/`, `docker/`, `.github/` | no | `make security-scan`, CI |
| Secret scanning | gitleaks (+ pytest regex self-tested scanner) | whole repo + history | no | `make secret-scan`, CI |
| SAST | semgrep (project rules + registry packs) | `app/`, `scripts/`, `docker/`, `.github/` | no | `make sast`, CI |
| Dependency / image scanning | trivy fs, trivy image, SBOM | `app/`, image | no | `make deps-scan image-scan`, CI |
| Workflow lint | actionlint | `.github/workflows` | no | `make workflow-lint`, CI |
| **Local cloud deployment** | Terraform apply/destroy against **moto** + live posture tests | `scripts/local-stack.sh`, `tests/security/live` | no | `make local-stack`, CI |
| Container runtime | docker compose + HTTPS smoke test | `scripts/smoke-test.sh` | no | `make smoke` |
| **Cloud posture** | same live tests + HTTPS checks against real AWS | `scripts/cloud-test.sh` | **yes** | `make cloud-test ENV=dev` |

## Required security properties → tests

| Property | terraform test | static pytest | live (moto / AWS) |
| --- | --- | --- | --- |
| Database not publicly accessible | `database.tftest.hcl` | `test_database_not_publicly_accessible` | `test_database_not_publicly_accessible_and_encrypted`, `test_database_subnets_are_private` |
| Private resources have no public IPs | `network.tftest.hcl`, `compute.tftest.hcl` | `test_no_public_ips_on_private_resources` | `test_running_instances_have_no_public_ip`, `test_launch_template_hardening`, `test_app_subnets_are_private` |
| Security groups restrictive | `network.tftest.hcl` | `test_only_alb_accepts_traffic_from_cidrs`, `test_expected_tier_flows`, `test_database_and_endpoints_have_no_egress_rules` | `test_security_groups_are_restrictive` |
| No dangerous IAM wildcards / admin policies / public trust | — | `test_iam_policies.py` (18 tests) | `test_iam_roles_least_privilege`, `test_iam_trust_relationships` |
| S3 not public | `logging.tftest.hcl` | `test_storage.py` | `test_buckets_not_public_and_encrypted` |
| Encryption enabled | `database`, `compute`, `security`, `logging` tftests | `test_encryption.py` | `test_kms_keys_rotate`, `test_secrets_use_customer_managed_key`, `test_cloudtrail_bucket_uses_kms`, `test_log_groups_encrypted_with_retention` |
| CloudTrail enabled | `logging.tftest.hcl` | `test_cloudtrail_enabled_and_hardened` | `test_cloudtrail_enabled` |
| Logging enabled | `network`/`logging`/`database` tftests | `test_logging.py` | `test_flow_logs_enabled`, `test_metric_filters_feed_alarms`, `test_security_alarms_exist_and_notify` |
| Secrets not hard-coded | `security.tftest.hcl` (write-only) | `test_secrets.py`, gitleaks | `test_secret_value_not_in_terraform_state` |
| Terraform valid | `stack.tftest.hcl`, `validation.tftest.hcl` | `test_terraform_fmt`, `test_terraform_validate` | full apply + destroy against moto |

## Tests that prove the tests work

A green suite is only meaningful if it can go red. During development:

* **Scanners**: a copy of the stack with `publicly_accessible = true` and
  `storage_encrypted = false` was flagged by checkov (CKV_AWS_17,
  CKV_AWS_16), tfsec (CRITICAL + HIGH) and trivy.
* **terraform test**: a copy with a public DB, IMDSv1 allowed and ALB
  ingress on port 80 failed 3 of 15 runs (`compute_hardening`,
  `database_hardening`, `network`).
* **Live posture tests**: against the deployed moto stack, an
  out-of-band `0.0.0.0/0 → 5432` rule and `PubliclyAccessible=true` made
  `test_security_groups_are_restrictive` and
  `test_database_not_publicly_accessible_and_encrypted` fail. After the
  revert, all 20 passed again.
* **Semgrep project rules**: a sample with Flask debug, `==` token
  comparison, f-string SQL, a logged password and `shell=True` triggered all
  5 rules.
* **Secret scanner self-test**: `test_scanner_detects_planted_secrets`.

## Results

See the [final verification run](#final-verification-run) below.

## Final verification run

`make all` on 2026-10-03 (Linux, Terraform v1.16.5), exit code 0. Full log
in `.local/final-run.log`; machine-readable reports in `reports/`.

| Stage | Result |
| --- | --- |
| `terraform fmt -check` | clean |
| `terraform validate` (root stack, bootstrap) | valid |
| tflint (+ AWS ruleset) | 0 issues |
| Unit tests (`tests/unit`) | 37 passed |
| `terraform test` (mocked provider) | 15 passed, 0 failed |
| Security tests (`tests/security`, static) | 96 passed, 20 skipped (live tests, run below) |
| checkov | 593 passed, 0 failed, 32 skipped (all in the [suppression register](../security/suppressions.md)) |
| tfsec | no problems detected |
| trivy config (Terraform + Dockerfile) | pass |
| gitleaks (working tree) | no leaks found |
| semgrep | 207 rules on 35 files, 0 findings |
| trivy fs (Python dependencies) | pass |
| actionlint | pass |
| trivy image (`sci-app:local`) | pass, SBOM in `reports/sbom-image.cdx.json` |
| Local stack: plan / apply to moto | 182 to add, applied |
| Live posture tests against the moto stack | 20 passed |
| Local stack: destroy | 182 destroyed |
| Container smoke test over HTTPS | 12/12 passed: health, readiness, 401 without/with wrong token, create/list notes, 400 on invalid input, HSTS/nosniff/CSP/X-Frame-Options headers, TLS 1.1 refused |
