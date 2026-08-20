# State lives in moto's emulated S3, exercising the same S3 backend (with
# native lock files) that real environments use.
bucket                      = "sci-local-tfstate"
key                         = "local/terraform.tfstate"
region                      = "us-east-1"
use_lockfile                = true
encrypt                     = true
use_path_style              = true
skip_credentials_validation = true
skip_requesting_account_id  = true
skip_metadata_api_check     = true
skip_region_validation      = true
endpoints = {
  s3  = "http://127.0.0.1:4566"
  sts = "http://127.0.0.1:4566"
}
