# CI/CD security

## Pipeline (`.github/workflows/ci.yml`)

```
Pull request / push to main
   │
   ├─ terraform ──────── fmt -check │ validate (root + bootstrap) │ terraform test (mocked) │ tflint (AWS ruleset)
   ├─ iac-scan ───────── checkov │ tfsec │ trivy config │ (SARIF → code scanning)
   ├─ secret-scan ────── gitleaks: working tree + FULL git history (fetch-depth 0)
   ├─ sast ───────────── semgrep (project rules + p/python, p/flask, p/secrets, p/dockerfile, p/github-actions) │ actionlint
   ├─ tests ──────────── pytest unit │ pytest security config tests │ terraform test
   ├─ container ──────── trivy dependency scan │ docker build │ trivy image (vuln + secret + misconfig) │ CycloneDX SBOM
   ├─ local-integration ─ deploy full stack to moto → live posture tests → destroy
   │
   └─ build ──────────── needs ALL of the above; builds the release image artefact
```

### Failure policy

| Gate | Fails the pipeline when |
| --- | --- |
| terraform fmt / validate / test / tflint | any error or failing assertion |
| checkov, tfsec, trivy config | **any** failed check, every severity (accepted exceptions are inline and registered, see `security/suppressions.md`) |
| gitleaks | any secret in the tree or in any commit |
| semgrep | any ERROR or WARNING finding |
| trivy (dependencies) | any HIGH or CRITICAL vulnerability |
| trivy (image) | any HIGH or CRITICAL vulnerability **with a fix available**, any embedded secret |
| pytest / terraform test | any failing test |
| actionlint | any workflow error |

SARIF uploads use `continue-on-error`, but they are **reporting only**. The
preceding scan step is the gate. No gate step has `continue-on-error`.

## Deployment (`.github/workflows/deploy.yml`)

1. Calls the complete CI workflow (`workflow_call`); deployment needs it to
   succeed.
2. Runs in the GitHub **environment `dev`** (configure required reviewers
   and a `main`-only branch policy).
3. Gets short-lived AWS credentials through **OIDC**
   (`aws-actions/configure-aws-credentials` + `id-token: write` on that job
   only). The IAM trust policy accepts exactly
   `repo:<owner>/<repo>:environment:dev` with audience `sts.amazonaws.com`.
4. `scripts/deploy-image.sh`: build → Trivy gate → push (immutable tag =
   commit SHA) → ECR scan-on-push gate (no CRITICAL) → update SSM tag →
   rolling instance refresh (≥ 50 % healthy) → wait for success.

No AWS credentials exist in the repository, the workflows or GitHub
secrets. The role ARN is a plain environment variable, which isn't
sensitive.

## Workflow hardening

* Every third-party action is pinned to a full **commit SHA** (with the
  version as a comment); Dependabot proposes updates.
* Workflow-level `permissions: contents: read`; individual jobs add only
  what they need (`security-events: write` for SARIF, `id-token: write` for
  the deploy job).
* `actions/checkout` with `persist-credentials: false`.
* No `pull_request_target`, and no untrusted `${{ github.event.* }}` input
  interpolated into `run:` scripts.
* Every job has `timeout-minutes`; `concurrency` cancels superseded CI runs
  and serialises deploys.
* Tools are not fetched by marketplace actions. `scripts/install-tools.sh`
  installs pinned versions and verifies SHA-256 checksums embedded in the
  repository. Combined with SHA-pinned actions, this blocks attacks like the
  March 2025 `tj-actions/changed-files` compromise, where existing version
  tags were re-pointed to a malicious commit.

These properties are enforced by `tests/security/static/test_ci.py`.

## Running CI locally

`make validate` runs the same gates the CI jobs run. `make all` adds the
local cloud deployment and the container smoke test.
