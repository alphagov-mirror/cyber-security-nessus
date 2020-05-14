resource "aws_lambda_function" "process_scans" {
  filename         = var.lambda_zip_location
  source_code_hash = filebase64sha256(var.lambda_zip_location)
  function_name    = "process_scans"
  role             = aws_iam_role.process_scans_exec_role.arn
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

resource "aws_cloudwatch_event_rule" "process_scans_24_hours" {
  name                = "nessus-24-hours"
  description         = "Fire nessus scan every 24 hours"
  schedule_expression = "cron(0 23 * * ? *)"
}

resource "aws_cloudwatch_event_target" "process_scans_24_hours_tg" {
  rule = aws_cloudwatch_event_rule.process_scans_24_hours.name
  arn  = aws_lambda_function.process_scans.arn
}

resource "aws_lambda_permission" "process_scans_allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.process_scans.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.process_scans_24_hours.arn
}
