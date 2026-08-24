resource "aws_lb" "payment_alb" {
  name               = "payment-public-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = ["subnet-11111111", "subnet-22222222"]
}

resource "aws_lb_listener" "payment_http" {
  load_balancer_arn = aws_lb.payment_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.payment_tg.arn
  }
}

resource "aws_lb_target_group" "payment_tg" {
  name        = "payment-service-tg"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = "vpc-12345678"
  target_type = "ip"
}

resource "aws_iam_role" "payment_service_role" {
  name = "payment-service-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "payment_service_s3_wildcard" {
  name = "payment-service-s3-wildcard"
  role = aws_iam_role.payment_service_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_s3_bucket" "financial_vault" {
  bucket = "enterprise-production-financial-vault"

  tags = {
    Environment = "production"
    DataClass   = "restricted-financial"
  }
}
