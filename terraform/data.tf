data "aws_ssm_parameter" "nessus_username" {
  name = "/nessus/username"
}

data "aws_ssm_parameter" "nessus_password" {
  name = "/nessus/password"
}

data "aws_ssm_parameter" "nessus_licence" {
  name = "/nessus/licence"
}

data "aws_ssm_parameter" "nessus_base_url" {
  name = "/nessus/public_base_url"
}

data "aws_ssm_parameter" "account_id" {
  name = "/nessus/account_id"
}

#
# data "aws_ssm_parameter" "nessus_access_key" {
#   name  = "/nessus/access_key"
# }
#
# data "aws_ssm_parameter" "nessus_secret_key" {
#   name  = "/nessus/secret_key"
# }
