resource "aws_acm_certificate" "fqdn" {
  validation_method = "DNS"
  domain_name       = var.fqdn
}

resource "aws_route53_record" "subdomain_validation" {
  name    = aws_acm_certificate.fqdn.domain_validation_options.0.resource_record_name
  type    = aws_acm_certificate.fqdn.domain_validation_options.0.resource_record_type
  records = [aws_acm_certificate.fqdn.domain_validation_options.0.resource_record_value]

  zone_id = data.aws_route53_zone.root_domain.id
  ttl     = 60
}

resource "aws_acm_certificate_validation" "subdomain_wildcard" {
  certificate_arn         = aws_acm_certificate.fqdn.arn
  validation_record_fqdns = [aws_route53_record.subdomain_validation.fqdn]
}
