resource "aws_acm_certificate" "fqdn" {
  validation_method = "DNS"
  domain_name       = var.fqdn
}

resource "aws_route53_record" "subdomain_validation" {
  for_each = {
    for dvo in aws_acm_certificate.fqdn.domain_validation_options : dvo.domain_name => {
      name = dvo.resource_record_name
      type = dvo.resource_record_type
    }
  }

  name    = each.value.name
  type    = each.value.type
  records = each.value.record
  zone_id = data.aws_route53_zone.nessus_domain.id
  ttl     = 60
}

resource "aws_acm_certificate_validation" "subdomain_wildcard" {
  certificate_arn         = aws_acm_certificate.fqdn.arn
  validation_record_fqdns = [for record in aws_route53_record.subdomain_validation : record.fqdn]
}
