variable "region" {
  description = "Region to deploy to and to watch."
  type        = string
  default     = "eu-west-1"
}

variable "name" {
  description = "Prefix for every resource."
  type        = string
  default     = "secrem"
}

variable "dry_run" {
  description = "true: detect and report only, change nothing. Switch to false only after reading the DRY_RUN findings."
  type        = bool
  default     = true
}

variable "scan_schedule" {
  description = "How often the full scan runs (catches anything the real-time events missed)."
  type        = string
  default     = "rate(6 hours)"
}

variable "approver_arns" {
  description = "IAM ARN patterns allowed to approve, reject and roll back. Wildcards allowed, e.g. arn:aws:sts::123456789012:assumed-role/AdminRole/*"
  type        = list(string)
  default     = []
}

variable "notify_emails" {
  description = "Addresses that get findings and approval requests (each must confirm the SNS subscription email)."
  type        = list(string)
  default     = []
}

variable "enable_trail" {
  description = "Create a CloudTrail trail so the real-time path is guaranteed to receive events. Set false if you already have one."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  type    = number
  default = 30
}
