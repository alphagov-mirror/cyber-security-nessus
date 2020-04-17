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
  default = "676218256630"
}

variable "nessus_lambda_functionname" {
  default = "nessus_scanner"
}

variable "nessus_lambda_handler" {
  default = "nessus_scanner.main"
}

variable "dependabot_lambda_memory" {
  default = 2048
}

variable "dependabot_lambda_timeout" {
  default = 900
}

