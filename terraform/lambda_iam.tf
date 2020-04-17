data "template_file" "nessus_lambda_trust" {
  template = file("${path.module}/json/interface_lambda/trust.json")
  vars     = {}
}

data "template_file" "nessus_lambda_policy" {
  template = file("${path.module}/json/interface_lambda/policy.json")
  vars = {
    region     = var.region
    account_id = var.aws_account_id
  }
}

resource "aws_iam_role" "nessus_lambda_exec_role" {
  name               = "nessus_lambda_exec_role"
  assume_role_policy = data.template_file.nessus_lambda_trust.rendered

  tags = {
    Service       = var.Service
    Environment   = var.Environment
    SvcOwner      = var.SvcOwner
    DeployedUsing = var.DeployedUsing
    SvcCodeURL    = var.SvcCodeURL
  }
}

resource "aws_iam_role_policy" "nessus_lambda_exec_role_policy" {
  name   = "nessus_lambda_exec_role_policy"
  role   = aws_iam_role.nessus_lambda_exec_role.id
  policy = data.template_file.nessus_lambda_policy.rendered
}
