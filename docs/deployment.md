# Deployment and cleanup runbook

## 0. Prerequisites

* Linux or macOS (x86_64/arm64), `bash`, `make`, `python3` (≥ 3.10) with
  `venv`, `curl`, `git`, Docker. For AWS: AWS CLI v2.
* All other tools (Terraform, checkov, tfsec, trivy, gitleaks, semgrep,
  tflint, actionlint, pytest, moto) are installed **into `./.tools`** at
  pinned versions, and each download is checked against an embedded SHA-256:

```bash
make tools
```

## 1. Local validation (no AWS account needed)

```bash
make validate      # fmt-check, validate, tflint, unit + security tests, all scanners
make local-stack   # deploy the FULL stack into a local AWS emulator (moto), run
                   # live posture tests, destroy it
make smoke         # build the container, run it with PostgreSQL, HTTPS smoke tests
make all           # all of the above
```

Reports (JSON / SARIF / JUnit / SBOM) are written to `reports/`.

## 2. Deploy to AWS (dev)

Use an administrator identity with MFA (e.g. `aws sso login --profile admin`
then `export AWS_PROFILE=admin`). Expected cost: [cost.md](cost.md).

```bash
# 2.1  One-time per account: remote state (KMS-encrypted, versioned, locked)
make bootstrap                 # review the plan, type "yes"
                               # writes terraform/environments/dev/backend.hcl

# 2.2  Review terraform/environments/dev/terraform.tfvars. At minimum set:
#        github_repository   = "<your-org>/<your-repo>"
#        allowed_account_ids = ["<your-account-id>"]
#      Optional: alarm_email, certificate_arn, alb_ingress_cidrs
#      If the account already has a GitHub OIDC provider:
#        create_github_oidc_provider = false

# 2.3  Plan, review, apply
make init  ENV=dev
make plan  ENV=dev             # read the plan
make apply ENV=dev             # applies exactly the reviewed plan

# 2.4  Ship the first application image (the ECR repository starts empty)
make deploy-image ENV=dev      # build → trivy gate → push → ECR scan gate → instance refresh

# 2.5  Verify the deployed environment
make cloud-test ENV=dev        # live posture tests + HTTPS checks against the real account
```

If you set `alarm_email`, confirm the SNS subscription e-mail.

### Enable the GitHub deployment pipeline

1. Push the repository to GitHub (`<owner>/<repo>` must match
   `github_repository`).
2. *Settings → Environments → New environment* `dev`; add required reviewers
   and restrict deployment branches to `main`.
3. In the `dev` environment add **variables** (not secrets; none are needed):
   * `AWS_DEPLOY_ROLE_ARN` = `terraform -chdir=terraform output -raw deployment_role_arn`
   * `AWS_REGION` = `us-east-1`
   * `SCI_NAME` = `sci-dev`
4. Protect `main` and require the `ci` checks before merging.

From then on, merges to `main` that touch `app/` or `docker/` deploy
automatically after the full CI passes. Use *Run workflow* for manual
deploys.

### Day-2 operations

```bash
make rotate-token ENV=dev                 # rotate the API token (old one stays valid until next rotation)
TAG=<previous-sha> make deploy-image ENV=dev   # roll back to an earlier immutable image
aws ssm start-session --target <instance-id>   # shell access without SSH (needs ssm:StartSession)
```

## 3. Cleanup (complete teardown)

```bash
# 3.1  Destroy the environment. Phase 1 lifts the guards (RDS/ALB deletion
#      protection, CloudTrail deny-delete policy, ECR force delete, secret
#      recovery window, final snapshot); phase 2 destroys everything.
make destroy ENV=dev CONFIRM=dev

# 3.2  (Optional) remove the state backend once NO environment is left
make destroy-bootstrap CONFIRM=destroy-state

# 3.3  Local artefacts
make clean                     # reports and local caches
rm -rf .tools                  # installed tools
```

Notes:

* The teardown deliberately skips the final RDS snapshot. Take a manual
  snapshot first if you need the data:
  `aws rds create-db-snapshot --db-instance-identifier sci-dev-db --db-snapshot-identifier sci-dev-keep`.
* KMS keys enter a 30-day pending-deletion window (cancellable with
  `aws kms cancel-key-deletion`).
* CloudWatch log groups, S3 log buckets and their contents are deleted.
  Archive CloudTrail logs first if your retention policy requires it.
* Verify that nothing is left:
  `aws resourcegroupstaggingapi get-resources --tag-filters Key=Project,Values=sci --query 'ResourceTagMappingList[].ResourceARN'`

## Exact command reference

| Goal | Command |
| --- | --- |
| Install tools | `make tools` |
| Offline validation | `make validate` |
| Full local pipeline | `make all` |
| Local cloud emulation only | `make local-stack` |
| Container smoke test | `make smoke` |
| Bootstrap state | `make bootstrap` |
| Plan / apply | `make init plan ENV=dev` then `make apply ENV=dev` |
| Deploy image | `make deploy-image ENV=dev` |
| Cloud tests | `make cloud-test ENV=dev` |
| Destroy | `make destroy ENV=dev CONFIRM=dev` |
| Remove state backend | `make destroy-bootstrap CONFIRM=destroy-state` |
