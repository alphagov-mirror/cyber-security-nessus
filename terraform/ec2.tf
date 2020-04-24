data "aws_ami" "cyber-security-nessus-ami" {
  most_recent = true
  owners      = ["aws-marketplace"]

  filter {
    name   = "product-code"
    values = ["8fn69npzmbzcs4blc4583jd0y"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "template_file" "nessus_userdata" {
  template = file("cloudinit/nessus_instance.yml")

  vars = {
    hostname        = "nessus-01"
    username        = data.aws_ssm_parameter.nessus_username.value
    password        = data.aws_ssm_parameter.nessus_password.value
    serial          = data.aws_ssm_parameter.nessus_licence.value
  }
}


resource "aws_instance" "nessus_instance" {
  ami           = data.aws_ami.cyber-security-nessus-ami.id
  instance_type = "t3a.xlarge"
  key_name      = "nessus_sp"
  user_data     = data.template_file.nessus_userdata.rendered
  monitoring    = "true"
  subnet_id     = aws_subnet.cyber-security-nessus-subnet.id

  vpc_security_group_ids = [
    aws_security_group.nessus-sg.id,
  ]

  root_block_device {
    volume_type = "gp2"
    volume_size = 30
  }

  tags = {
    Name      = "Nessus Scanning Instance"
    ManagedBy = "terraform"
  }
}
