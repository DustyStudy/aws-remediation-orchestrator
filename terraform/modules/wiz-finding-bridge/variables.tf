variable "name_prefix" {
  type        = string
  description = "Prefix used for naming all resources created by this module."
  default     = "wiz-finding-bridge"
}

variable "notification_email" {
  type        = string
  description = "Optional email address to subscribe to the SNS topic. Leave empty to skip."
  default     = ""
}

variable "minimum_severity" {
  type        = string
  description = <<-EOT
    Lowest severity to import and notify on: CRITICAL, HIGH, MEDIUM, LOW,
    or INFORMATIONAL. A finding whose severity can't be resolved from
    severity_field_path is always processed regardless of this setting
    (fails open, not silent), and imported as INFORMATIONAL.
  EOT
  default     = "HIGH"

  validation {
    condition     = contains(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"], var.minimum_severity)
    error_message = "minimum_severity must be one of CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL."
  }
}

variable "severity_field_path" {
  type        = string
  description = "Dot-notation path to the severity field in the Wiz webhook payload."
  default     = "severity"
}

variable "title_field_path" {
  type        = string
  description = "Dot-notation path to a human-readable title/rule-name field in the payload."
  default     = "title"
}

variable "resource_field_path" {
  type        = string
  description = <<-EOT
    Dot-notation path to a resource object/identifier field in the
    payload. Defaults to "primaryResource", an object in Wiz's schema -
    rendered as JSON in the report since its internal shape isn't
    assumed.
  EOT
  default     = "primaryResource"
}

variable "resource_id_field_path" {
  type        = string
  description = <<-EOT
    Dot-notation path to a string naming the resource, ideally its AWS
    ARN, used as the imported finding's Resources[0].Id. Playbooks need
    an ARN to act on. Empty (the default) imports every finding with a
    placeholder id: the orchestrator logs it, but no playbook can act on
    it. Set this from the raw payload in your first notification.
  EOT
  default     = ""
}

variable "id_field_path" {
  type        = string
  description = "Dot-notation path to Wiz's own id for the issue. Repeat deliveries with the same id update one Security Hub finding. If it doesn't resolve, a hash of the payload is used."
  default     = "id"
}

variable "code_signing_config_arn" {
  type        = string
  description = "Optional ARN of an existing aws_lambda_code_signing_config to enforce on this function. Leave null to skip."
  default     = null
}

variable "throttle_burst_limit" {
  type        = number
  description = "API Gateway stage-level burst limit for the webhook route."
  default     = 10
}

variable "throttle_rate_limit" {
  type        = number
  description = "API Gateway stage-level steady-state requests-per-second limit."
  default     = 5
}
