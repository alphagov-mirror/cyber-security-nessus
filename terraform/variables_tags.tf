variable "Service" {
  description = "Service Name"
  type        = string
  default     = "Nessus"
}

variable "SvcOwner" {
  description = "Service Owner"
  type        = string
  default     = "cyber security"
}

variable "Environment" {
  description = "Service Environment"
  type        = string
  default     = "prod"
}

variable "DeployedUsing" {
  description = "Deployed Using"
  type        = string
  default     = "Terraform"
}

variable "SvcCodeURL" {
  description = "Service Code URL"
  type        = string
  default     = "tbd"
}
