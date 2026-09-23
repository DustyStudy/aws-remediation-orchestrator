variable "name_prefix" {
  type        = string
  description = "Prefix used for naming all resources created by this module."
  default     = "remediation-orchestrator"
}

variable "notification_email" {
  type        = string
  description = "Email address subscribed to the results/approval SNS topic. Leave empty to skip and wire your own subscription (Slack, PagerDuty, etc.) to the topic output instead."
  default     = ""
}

variable "approval_timeout_seconds" {
  type        = number
  description = "How long an approval-required remediation waits for a human response before the Step Functions task times out and the finding is left unremediated."
  default     = 86400 # 24 hours
}

variable "evidence_export_schedule" {
  type        = string
  description = "EventBridge schedule expression for exporting ledger entries as compliance evidence."
  default     = "rate(1 day)"
}

variable "evidence_lookback_hours" {
  type        = number
  description = "How far back the evidence exporter looks each run. Should be >= the evidence_export_schedule interval so no ledger entry is skipped."
  default     = 24
}

variable "policy_registry_seed" {
  description = <<-EOT
    Initial policy-registry items, keyed by match_id. See docs/POLICY_REGISTRY.md
    for the full schema. A "default" item is required - it's the fallback
    applied when nothing else matches, and Terraform will fail validation
    without one.

    action_document may reference either an SSM document this module
    creates (terraform/ssm-documents.tf) or one from another deployment
    entirely, as long as its ARN is included in external_ssm_document_arns
    so this module's execution role is granted permission to start it.
  EOT
  type = map(object({
    match_field           = string
    match_value           = string
    mode                  = string
    action_document       = optional(string, "")
    action_document_owner = optional(string, "self")
    nist_controls         = optional(list(string), [])
    max_actions_per_hour  = optional(number, 10)
    severity_threshold    = optional(string, null)
    description           = string
  }))

  validation {
    condition     = contains(keys(var.policy_registry_seed), "default")
    error_message = "policy_registry_seed must include a \"default\" item."
  }
}

variable "external_ssm_document_arns" {
  type        = list(string)
  description = "ARNs of SSM Automation documents owned by other deployments (e.g. aws-cloud-security-toolbox) that a policy_registry_seed item points at via action_document. The orchestrator's execution role is granted ssm:StartAutomationExecution on exactly these ARNs plus the documents it creates itself - nothing broader."
  default     = []
}

variable "evidence_bucket_force_destroy" {
  type        = bool
  description = "Allow the evidence S3 bucket to be destroyed even if it has objects in it. Leave false in any environment producing real compliance evidence."
  default     = false
}

variable "code_signing_config_arn" {
  type        = string
  description = "Optional ARN of an existing aws_lambda_code_signing_config to enforce code-signature validation on every function this module creates. Leave null to skip."
  default     = null
}

variable "lambda_log_retention_days" {
  type        = number
  description = "CloudWatch Logs retention for every Lambda function's log group."
  default     = 365
}

variable "enable_lambda_reserved_concurrency" {
  type        = bool
  description = <<-EOT
    Whether to set reserved_concurrent_executions on this module's Lambda
    functions. The defaults (10-20 per function, ~130 total) assume an
    account with normal Lambda concurrency headroom (the standard 1,000
    unreserved default). A newly created account can start with an
    account-wide concurrency limit as low as 10, in which case reserving
    concurrency on even one function leaves less than the minimum
    unreserved amount AWS requires and every aws_lambda_function apply
    fails with "decreases account's UnreservedConcurrentExecution below
    its minimum value". Set to false to deploy unreserved (relying on the
    account's shared pool) until a quota increase is granted, or in a
    throwaway test account where per-function isolation doesn't matter.
    See docs/PROOF.md.
  EOT
  default     = true
}

variable "tags" {
  type        = map(string)
  description = "Additional tags applied to every resource this module creates."
  default     = {}
}
