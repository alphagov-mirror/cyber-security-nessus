resource "aws_cloudwatch_log_group" "nessus_data" {
  name = "/gds/nessus-data"

  tags = {
    Environment = "production"
    Application = "Nessus scans"
  }
}

resource "aws_cloudwatch_log_subscription_filter" "log_subscription" {
  name            = "log_subscription"
  log_group_name  = "/gds/nessus-data"
  filter_pattern  = ""
  destination_arn = "arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prod"
}