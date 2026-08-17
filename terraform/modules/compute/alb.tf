#------------------------------------------------------------- certificate
# Production: pass certificate_arn for an ACM certificate on a real domain.
# Dev without a domain: a self-signed certificate is generated so the
# listener is still HTTPS-only. Its private key lives in the (KMS-encrypted,
# access-restricted) Terraform state; see docs/encryption.md.
resource "tls_private_key" "self_signed" {
  count       = var.certificate_arn == null ? 1 : 0
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_self_signed_cert" "self_signed" {
  count                 = var.certificate_arn == null ? 1 : 0
  private_key_pem       = tls_private_key.self_signed[0].private_key_pem
  validity_period_hours = 24 * 90
  early_renewal_hours   = 24 * 14
  dns_names             = [var.certificate_domain]
  allowed_uses          = ["digital_signature", "key_encipherment", "server_auth"]

  subject {
    common_name  = var.certificate_domain
    organization = "Secure Cloud Infrastructure (dev)"
  }
}

resource "aws_acm_certificate" "self_signed" {
  count            = var.certificate_arn == null ? 1 : 0
  private_key      = tls_private_key.self_signed[0].private_key_pem
  certificate_body = tls_self_signed_cert.self_signed[0].cert_pem

  lifecycle {
    create_before_destroy = true
  }
}

locals {
  certificate_arn = var.certificate_arn != null ? var.certificate_arn : aws_acm_certificate.self_signed[0].arn
}

#-------------------------------------------------------------- load balancer
resource "aws_lb" "this" {
  #checkov:skip=CKV2_AWS_20:There is no HTTP listener at all, so there is nothing to redirect; only HTTPS is exposed.
  name                       = "${var.name}-alb"
  load_balancer_type         = "application"
  internal                   = false #tfsec:ignore:aws-elb-alb-not-public -- internet-facing entry point by design
  subnets                    = var.public_subnet_ids
  security_groups            = [var.alb_security_group_id]
  drop_invalid_header_fields = true
  desync_mitigation_mode     = "strictest"
  enable_deletion_protection = var.alb_deletion_protection
  enable_http2               = true
  idle_timeout               = 60
  xff_header_processing_mode = "append"
  ip_address_type            = "ipv4"

  access_logs {
    bucket  = var.alb_logs_bucket
    prefix  = "access"
    enabled = true
  }

  connection_logs {
    bucket  = var.alb_logs_bucket
    prefix  = "connection"
    enabled = true
  }
}

# ALB -> target traffic is re-encrypted (HTTPS to the app's TLS port).
resource "aws_lb_target_group" "app" {
  name                 = "${var.name}-app"
  vpc_id               = var.vpc_id
  port                 = var.app_port
  protocol             = "HTTPS"
  target_type          = "instance"
  deregistration_delay = 30

  health_check {
    enabled             = true
    protocol            = "HTTPS"
    path                = "/health"
    port                = "traffic-port"
    matcher             = "200"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

# The only listener. No port 80 listener exists, so plaintext HTTP is not
# served at all. TLS policy allows only TLS 1.3 and TLS 1.2 with
# forward-secret AEAD ciphers.
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"
  certificate_arn   = local.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}
