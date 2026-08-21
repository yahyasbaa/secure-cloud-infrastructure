# Negative tests: unsafe inputs are rejected before anything is created.

mock_provider "aws" {
  source = "./tests/mocks"
}

run "rejects_single_az" {
  command = plan
  variables {
    az_count = 1
  }
  expect_failures = [var.az_count]
}

run "rejects_wildcard_github_repo" {
  command = plan
  variables {
    github_repository = "example-org/*"
  }
  expect_failures = [var.github_repository]
}

run "rejects_wildcard_github_environment" {
  command = plan
  variables {
    github_environment = "*"
  }
  expect_failures = [var.github_environment]
}

run "rejects_invalid_ingress_cidr" {
  command = plan
  variables {
    alb_ingress_cidrs = ["not-a-cidr"]
  }
  expect_failures = [var.alb_ingress_cidrs]
}

run "rejects_empty_ingress_list" {
  command = plan
  variables {
    alb_ingress_cidrs = []
  }
  expect_failures = [var.alb_ingress_cidrs]
}

run "rejects_unknown_environment" {
  command = plan
  variables {
    environment = "production-ish"
  }
  expect_failures = [var.environment]
}
