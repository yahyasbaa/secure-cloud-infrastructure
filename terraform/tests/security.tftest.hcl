mock_provider "aws" {
  source = "./tests/mocks"
}

variables {
  name               = "sci-test"
  account_id         = "111122223333"
  partition          = "aws"
  region             = "us-east-1"
  trail_name         = "sci-test-trail"
  log_group_prefixes = ["/sci-test/"]
  app_token_version  = 1
}

run "encryption_and_secrets" {
  command = apply

  module {
    source = "./modules/security"
  }

  assert {
    condition     = aws_kms_key.data.enable_key_rotation && aws_kms_key.logs.enable_key_rotation
    error_message = "automatic KMS key rotation must be enabled"
  }

  assert {
    condition     = aws_kms_key.data.deletion_window_in_days == 30 && aws_kms_key.logs.deletion_window_in_days == 30
    error_message = "KMS keys must keep the maximum 30-day deletion window"
  }

  assert {
    condition     = aws_kms_key.data.arn != aws_kms_key.logs.arn || aws_kms_key.data.description != aws_kms_key.logs.description
    error_message = "data and log encryption must use separate keys"
  }

  assert {
    condition     = aws_secretsmanager_secret.app_token.kms_key_id == aws_kms_key.data.arn
    error_message = "the application secret must be encrypted with the data CMK"
  }

  # The token is written through a write-only attribute: nothing in state.
  assert {
    condition     = aws_secretsmanager_secret_version.app_token.secret_string == null && aws_secretsmanager_secret_version.app_token.secret_string_wo == null
    error_message = "secret value must never be stored in Terraform state"
  }

  assert {
    condition     = aws_secretsmanager_secret.app_token.recovery_window_in_days == 7
    error_message = "secrets must be recoverable for 7 days unless explicitly torn down"
  }

  assert {
    condition     = aws_secretsmanager_secret_policy.app_token.block_public_policy
    error_message = "secret resource policy must block public policies"
  }
}
