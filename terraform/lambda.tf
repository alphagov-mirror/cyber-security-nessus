resource "aws_lambda_function" "nessus_lambda" {
  filename         = var.lambda_zip_location
  source_code_hash = filebase64sha256(var.lambda_zip_location)
  function_name    = "process_scans"
  role             = aws_iam_role.nessus_lambda_exec_role.arn
  handler          = "process_scans.main"
  runtime          = var.runtime
  timeout          = "900"
  memory_size      = 2048

  vpc_config {
    subnet_ids         = [aws_subnet.cyber-security-nessus-subnet.id]
    security_group_ids = [aws_security_group.nessus-sg.id]
  }

  tags = {
    Service       = var.Service
    Environment   = var.Environment
    SvcOwner      = var.SvcOwner
    DeployedUsing = var.DeployedUsing
    SvcCodeURL    = var.SvcCodeURL
  }
}

resource "aws_cloudwatch_event_rule" "nessus_lambda_24_hours" {
  name                = "nessus-24-hours"
  description         = "Fire nessus scan every 24 hours"
  schedule_expression = "cron(0 23 * * ? *)"
}

resource "aws_cloudwatch_event_target" "nessus_lambda_24_hours_tg" {
  rule = aws_cloudwatch_event_rule.nessus_lambda_24_hours.name
  arn  = aws_lambda_function.nessus_lambda.arn
}

resource "aws_lambda_permission" "nessus_lambda_allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.nessus_lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.nessus_lambda_24_hours.arn
}
