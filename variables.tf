# SPDX-License-Identifier: PMPL-1.0-or-later
# Terraform variables for Cloudflare DNS management

variable "cloudflare_api_token" {
  description = "Cloudflare API token with DNS edit permissions"
  type        = string
  sensitive   = true
}

variable "cloudflare_account_id" {
  description = "Cloudflare account ID"
  type        = string
  default     = "b72dd54ed3ee66088950c82e0301edbb"
}
