resource "aws_acm_certificate" "fqdn" {
  validation_method = "DNS"
  domain_name       = var.fqdn
}

resource "aws_route53_record" "subdomain_validation" {
  for_each = {
    for domain_validation_option in aws_acm_certificate.fqdn.domain_validation_options : domain_validation_option.domain_name => {
      name = domain_validation_option.resource_record_name
      type = domain_validation_option.resource_record_type
    }
  }

  name    = each.value.name
  type    = each.value.type
  records = [each.value.record]
  zone_id = data.aws_route53_zone.nessus_domain.id
  ttl     = 60
}

resource "aws_acm_certificate_validation" "subdomain_wildcard" {
  certificate_arn         = aws_acm_certificate.fqdn.arn
  validation_record_fqdns = [for record in aws_route53_record.subdomain_validation : record.fqdn]
}
