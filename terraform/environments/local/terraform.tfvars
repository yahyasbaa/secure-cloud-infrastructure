# LOCAL validation environment: runs the full stack against a moto AWS
# emulator on 127.0.0.1 (see scripts/local-stack.sh). Nothing here touches
# a real AWS account; moto's fixed account ID is enforced below.
project             = "sci"
environment         = "local"
aws_region          = "us-east-1"
allowed_account_ids = ["123456789012"]
s3_use_path_style   = true

github_repository  = "example-org/secure-cloud-infrastructure"
github_environment = "dev"

# Disposable environment: allow a clean teardown.
alb_deletion_protection = false
db_deletion_protection  = false
db_skip_final_snapshot  = true
allow_force_destroy     = true

enable_waf       = true
enable_guardduty = true
