data "aws_ssm_parameter" "nessus_username" {
  name = "/nessus/username"
}

data "aws_ssm_parameter" "nessus_password" {
  name = "/nessus/password"
}

data "aws_ssm_parameter" "nessus_licence" {
  name = "/nessus/licence"
}
