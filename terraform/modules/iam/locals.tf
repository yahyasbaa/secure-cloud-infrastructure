locals {
  ecr_repository_arn      = "arn:${var.partition}:ecr:${var.region}:${var.account_id}:repository/${var.ecr_repository_name}"
  image_tag_parameter_arn = "arn:${var.partition}:ssm:${var.region}:${var.account_id}:parameter${var.image_tag_parameter_name}"
}
