data "aws_ssm_parameter" "al2023" {
  count = var.ami_id == null ? 1 : 0
  name  = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-${local.architecture}"
}

locals {
  # Graviton families (t4g, m7g, ...) need the arm64 AMI.
  architecture = can(regex("^[a-z]+[0-9]+g[a-z]*\\.", var.instance_type)) ? "arm64" : "x86_64"
  ami_id       = var.ami_id != null ? var.ami_id : nonsensitive(data.aws_ssm_parameter.al2023[0].value)

  user_data = templatefile("${path.module}/templates/user_data.sh.tftpl", {
    region              = var.region
    account_id          = var.account_id
    ecr_repository      = aws_ecr_repository.app.name
    image_tag_parameter = aws_ssm_parameter.image_tag.name
    app_log_group       = var.app_log_group_name
    app_port            = var.app_port
    app_secret_arn      = var.app_secret_arn
    db_secret_arn       = var.db_secret_arn
    db_host             = var.db_address
    db_port             = var.db_port
    db_name             = var.db_name
  })
}

resource "aws_launch_template" "app" {
  name                   = "${var.name}-app"
  description            = "Hardened application host"
  image_id               = local.ami_id
  instance_type          = var.instance_type
  update_default_version = true
  ebs_optimized          = true
  user_data              = base64encode(local.user_data)

  iam_instance_profile {
    arn = var.instance_profile_arn
  }

  # IMDSv2 only; hop limit 1 so metadata credentials cannot be relayed off the
  # host; instance tags not exposed through IMDS.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  network_interfaces {
    associate_public_ip_address = false
    delete_on_termination       = true
    security_groups             = [var.app_security_group_id]
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = var.root_volume_size
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = var.data_kms_key_arn
      delete_on_termination = true
    }
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags          = { Name = "${var.name}-app" }
  }

  tag_specifications {
    resource_type = "volume"
    tags          = { Name = "${var.name}-app" }
  }
}

resource "aws_autoscaling_group" "app" {
  name                      = var.asg_name
  vpc_zone_identifier       = var.app_subnet_ids
  min_size                  = var.asg_min_size
  max_size                  = var.asg_max_size
  desired_capacity          = var.asg_desired_capacity
  health_check_type         = "ELB"
  health_check_grace_period = 300
  target_group_arns         = [aws_lb_target_group.app.arn]
  service_linked_role_arn   = var.autoscaling_slr_arn
  default_instance_warmup   = 120
  # Don't block `terraform apply` on healthy capacity: on the very first apply
  # the ECR repository is still empty, so hosts cannot become healthy until
  # the deploy workflow pushes an image. Health is enforced by the ALB health
  # check, instance refresh min_healthy_percentage and the unhealthy-hosts alarm.
  wait_for_capacity_timeout = "0"
  enabled_metrics           = ["GroupDesiredCapacity", "GroupInServiceInstances", "GroupTerminatingInstances", "GroupTotalInstances"]

  launch_template {
    id      = aws_launch_template.app.id
    version = aws_launch_template.app.latest_version
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.name}-app"
    propagate_at_launch = true
  }
}
