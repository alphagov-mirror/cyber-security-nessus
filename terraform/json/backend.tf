terraform {
  backend "s3" {
    bucket = "cyber-security-nessus-state-bucket-01"
    key    = "nessus.tfstate"
    region = "${var.region}"
  }
}
