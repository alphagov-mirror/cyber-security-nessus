variable "lambda_zip_location" {
  default = "../nessus_lambda.zip"
}

variable "runtime" {
  description = "runtime for lambda"
  default     = "python3.7"
}

variable "region" {
  type    = string
  default = "eu-west-2"
}

variable "aws_account_id" {
  default = data.aws_ssm_parameter.account_id
}

variable "dependabot_lambda_memory" {
  default = 2048
}

variable "dependabot_lambda_timeout" {
  default = 900
}

variable "fqdn" {
  type    = string
  default = data.aws_ssm_parameter.nessus_base_url
}
