# Global parameters
variable "resource_prefix" {
  type        = string
  description = "Prefix name for AWS Backup resources"
}

variable "copy_account_id" {
  type        = string
  description = "Target AWS account Id for cross-account copies"
}

variable "organization_id" {
  type        = string
  description = "AWS Organization ID"
}

variable "tag_key_scp_protection" {
  type        = string
  description = "Tag key for AWS Organizations protected resources with SCPs"
}

variable "tag_value_scp_protection" {
  type        = string
  description = "Tag value for AWS Organizations protected resources with SCPs"
}

# Parameters for AWS Backup notification features
variable "install_notifications" {
  type        = bool
  description = "Do you want to deploy central backup notification features?"
}

variable "main_account_id" {
  type        = string
  description = "AWS account ID of AWS Organization main account"
}

variable "main_region" {
  type        = string
  description = "Second AWS Region where resources must be protected - They will be copied into region_A on copy_account_id"
}
