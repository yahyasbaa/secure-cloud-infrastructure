# Private image registry: immutable tags (a deployed tag can never be
# silently replaced), scan on push, KMS encryption, bounded history.
resource "aws_ecr_repository" "app" {
  name                 = var.ecr_repository_name
  image_tag_mutability = "IMMUTABLE"
  force_delete         = var.ecr_force_delete

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = var.data_kms_key_arn
  }
}

resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images after 7 days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 7
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep the 30 most recent images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 30
        }
        action = { type = "expire" }
      },
    ]
  })
}

# The image tag the hosts run. CI updates this value after pushing a new,
# scanned image, then starts an instance refresh.
resource "aws_ssm_parameter" "image_tag" {
  #checkov:skip=CKV2_AWS_34:Holds a public container image tag, not sensitive data; String keeps the deploy role free of KMS permissions.
  name        = var.image_tag_parameter_name
  description = "Container image tag deployed to ${var.asg_name}"
  type        = "String"
  value       = var.app_image_tag

  lifecycle {
    ignore_changes = [value] # owned by the deployment pipeline after creation
  }
}
