# Whole-stack smoke test: the complete configuration plans and "applies"
# against a mocked AWS provider, entirely offline.

mock_provider "aws" {
  source = "./tests/mocks"
}

variables {
  environment = "test"
}

run "full_stack_applies_offline" {
  command = apply

  assert {
    condition     = output.asg_name == "sci-test-app"
    error_message = "unexpected ASG name"
  }

  assert {
    condition     = length(output.alarm_names) == 24
    error_message = "expected 17 log-based + 6 metric alarms + 1 WAF alarm"
  }

  assert {
    condition = alltrue([for a in [
      "sci-test-unauthorized-api-calls",
      "sci-test-console-signin-failures",
      "sci-test-security-group-changes",
      "sci-test-iam-policy-changes",
      "sci-test-unexpected-secret-access",
      "sci-test-app-auth-failures",
      "sci-test-db-auth-failures",
      "sci-test-alb-request-anomaly",
    ] : contains(output.alarm_names, a)])
    error_message = "a required security alarm is missing"
  }
}

run "waf_alarm_follows_toggle" {
  command = plan

  variables {
    enable_waf = false
  }

  assert {
    condition     = !contains(output.alarm_names, "sci-test-waf-blocked-spike")
    error_message = "WAF alarm must not exist when WAF is disabled"
  }
}
