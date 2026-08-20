# DEV environment (real AWS). Review every value before `make plan ENV=dev`.
project     = "sci"
environment = "dev"
aws_region  = "us-east-1"

# Strongly recommended: pin the account so this config can never be applied
# to the wrong one.
# allowed_account_ids = ["111122223333"]

# Repository + GitHub environment trusted by the OIDC deployment role.
github_repository  = "example-org/secure-cloud-infrastructure"
github_environment = "dev"

# Set false if the account already has the GitHub OIDC provider.
create_github_oidc_provider = true

# Restrict who can reach the ALB (default: whole internet, WAF-protected).
# alb_ingress_cidrs = ["203.0.113.0/24"]

# Supply a real ACM certificate for a domain you own; otherwise a self-signed
# certificate is generated (browsers will warn).
# certificate_arn = "arn:aws:acm:us-east-1:111122223333:certificate/..."

# alarm_email = "security-team@example.com"

# Free-Tier friendly defaults (see docs/cost.md).
instance_type               = "t3.micro"
db_instance_class           = "db.t4g.micro"
db_multi_az                 = false
interface_endpoint_az_count = 1
enable_waf                  = true
enable_guardduty            = false
