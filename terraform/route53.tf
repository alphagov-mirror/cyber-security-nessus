data "aws_route53_zone" "nessus_domain" {
  name = var.fqdn
}

resource "aws_route53_record" "fqdn" {
  zone_id = data.aws_route53_zone.nessus_domain.zone_id
  name    = var.fqdn
  type    = "A"

  alias {
    name                   = aws_lb.alb.dns_name
    zone_id                = aws_lb.alb.zone_id
    evaluate_target_health = false
  }
}
