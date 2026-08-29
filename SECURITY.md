# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Report them
privately through GitHub's *Security → Report a vulnerability* (private
vulnerability reporting) on this repository. Include the affected file or
component, reproduction steps and the impact you expect.

You can expect an acknowledgement within 3 working days and an initial
assessment within 10 working days. Fixes for confirmed issues are
developed in a private fork and credited to the reporter unless you prefer
otherwise.

## Scope

In scope: the Terraform configuration, the application in `app/`, the
container image, the CI/CD workflows and the helper scripts. Out of scope:
findings that need an already-compromised AWS administrator, denial of
service by volume against a deployment you don't own, and third-party
services.

Never test against an AWS environment you don't own.

## Supported versions

Only the latest commit on `main` receives security fixes.

## Security practices in this repository

| Area | Practice |
| --- | --- |
| Secrets | Never committed. AWS secrets live in Secrets Manager (CMK-encrypted); Terraform writes the API token write-only so it never reaches state; RDS generates and rotates the DB password. `.env.example` holds placeholders only. gitleaks scans the tree and the full history on every PR |
| Credentials | No IAM users or access keys. CI uses GitHub OIDC (repo + environment pinned). Human roles require MFA |
| Least privilege | Customer-written policies only, no wildcard actions, `Resource "*"` only for APIs without resource-level permissions (verified automatically) |
| Supply chain | Actions pinned by commit SHA; tools pinned and SHA-256 verified; Python dependencies hash-locked; base images pinned by digest; SBOM per image; Dependabot |
| Policy as code | checkov, tfsec, trivy, tflint, semgrep, `terraform test` and pytest security tests block merges. Exceptions are inline, justified and registered in `security/suppressions.md` |
| Detection | CloudTrail (multi-region, validated), VPC flow logs, structured application security events, 24 CloudWatch alarms, real-time EventBridge rules, optional GuardDuty |

The full threat model is in [docs/threat-model.md](docs/threat-model.md).
