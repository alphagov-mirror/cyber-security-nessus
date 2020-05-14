locals {
  # The gds-ips below are set to the GDS gds egress ips, this local var is used to whitelist inbound ssh connections
  gds-ips = [
    "85.133.67.244/32",
    "213.86.153.212/32",
    "213.86.153.213/32",
    "213.86.153.214/32",
    "213.86.153.235/32",
    "213.86.153.236/32",
    "213.86.153.237/32",
    "35.177.118.205/32",
    "3.9.45.234/32",
    "10.1.1.0/24"
  ]
}

resource "aws_security_group" "nessus-sg" {
  name        = "nessus-sg"
  description = "Nessus Instance Security Group"
  vpc_id      = aws_vpc.cyber-security-nessus.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = local.gds-ips
  }

  ingress {
    from_port   = 8834
    to_port     = 8834
    protocol    = "tcp"
    cidr_blocks = local.gds-ips
  }

  ingress {
    from_port       = 8834
    to_port         = 8834
    protocol        = "tcp"
    security_groups = [aws_security_group.nessus-alb-sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = -1
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name      = "Nessus Scanning Instance"
    ManagedBy = "terraform"
  }
}

resource "aws_security_group" "nessus-alb-sg" {
  name        = "nessus-alb-sg"
  description = "ALB Security Group for Nessus"
  vpc_id      = aws_vpc.cyber-security-nessus.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = local.gds-ips
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = local.gds-ips
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = -1
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name      = "ALB for Nessus Scanning Instance"
    ManagedBy = "terraform"
  }
}

resource "aws_vpc" "cyber-security-nessus" {
  cidr_block = "10.1.0.0/16"

  tags = {
    Name      = "Cyber Security Nessus VPC"
    ManagedBy = "terraform"
  }
}

resource "aws_internet_gateway" "cyber-security-nessus-igw" {
  vpc_id = aws_vpc.cyber-security-nessus.id

  tags = {
    Name      = "Cyber Security Nessus Internet Gateway"
    ManagedBy = "terraform"
  }
}

resource "aws_subnet" "cyber-security-nessus-subnet" {
  vpc_id                  = aws_vpc.cyber-security-nessus.id
  cidr_block              = "10.1.1.0/24"
  availability_zone       = "eu-west-2a"
  map_public_ip_on_launch = true

  tags = {
    Name      = "Cyber Security Nessus Subnet in London AZ a"
    ManagedBy = "terraform"
  }
}

# ALB requires two subnets in different AZs, so we create this
# subnet just for it
resource "aws_subnet" "cyber-security-nessus-subnet-b" {
  vpc_id                  = aws_vpc.cyber-security-nessus.id
  cidr_block              = "10.1.2.0/24"
  availability_zone       = "eu-west-2b"
  map_public_ip_on_launch = true

  tags = {
    Name      = "Cyber Security Nessus Subnet in London AZ b"
    ManagedBy = "terraform"
  }
}

resource "aws_route_table" "cyber-security-nessus-route-table" {
  vpc_id = aws_vpc.cyber-security-nessus.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.cyber-security-nessus-igw.id
  }

  tags = {
    Name      = "Cyber Security Nessus Routing Table"
    ManagedBy = "terraform"
  }
}

resource "aws_route_table_association" "cyber-security-nessus-association" {
  subnet_id      = aws_subnet.cyber-security-nessus-subnet.id
  route_table_id = aws_route_table.cyber-security-nessus-route-table.id
}

resource "aws_route_table_association" "cyber-security-nessus-association-b" {
  subnet_id      = aws_subnet.cyber-security-nessus-subnet-b.id
  route_table_id = aws_route_table.cyber-security-nessus-route-table.id
}
