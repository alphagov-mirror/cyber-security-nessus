resource "aws_lb" "alb" {
  name               = "nessus-load-balancer"
  load_balancer_type = "application"
  security_groups    = [aws_security_group.nessus-sg.id]
  subnets            = [aws_subnet.cyber-security-nessus-subnet.id]
}

# HTTP version... I'm not sure if we still need this
#resource "aws_lb_target_group" "nessus-web" {
#  name     = "nessus-web"
#  port     = 8834
#  protocol = "HTTP"
#  vpc_id   = aws_vpc.cyber-security-nessus.id
#  health_check {
#    path    = "/"
#    matcher = "200"
#  }
#}

resource "aws_lb_target_group" "nessus_web" {
  name     = "nessus-web"
  port     = 8834
  protocol = "HTTPS"
  vpc_id   = aws_vpc.cyber-security-nessus.id
  health_check {
    protocol = "HTTPS"
    path     = "/"
    matcher  = "200"
  }
}

resource "aws_lb_target_group_attachment" "nessus_web" {
  target_group_arn = aws_lb_target_group.nessus_web.arn
  target_id        = aws_instance.nessus_instance.id
  lifecycle {
    create_before_destroy = true
  }
}


resource "aws_lb_listener" "http_to_https" {
  load_balancer_arn = aws_lb.alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      protocol    = "HTTPS"
      port        = "443"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.alb.arn
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate.fqdn.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.nessus_web.arn
  }
}
