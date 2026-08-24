resource "aws_lb" "public_alb" {
  name               = "production-public-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = ["subnet-1111", "subnet-2222"]

  tags = {
    Environment = "production"
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.public_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.order_tg.arn
  }
}

resource "aws_lb_target_group" "order_tg" {
  name        = "order-service-tg"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = "vpc-12345"
  target_type = "ip"
}
