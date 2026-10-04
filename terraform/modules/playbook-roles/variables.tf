variable "name_prefix" {
  type        = string
  description = "Must match the hub deployment's name_prefix: the hub finds these roles by name."
  default     = "remediation-orchestrator"
}

variable "notification_topic_arn" {
  type        = string
  description = "The hub's notifications topic. Every playbook publishes its result there."
}

variable "data_key_arn" {
  type        = string
  description = "The hub's data KMS key, which encrypts the notifications topic."
}

variable "region" {
  type        = string
  description = "Region the playbooks run in, for the region-scoped EC2 permissions. Defaults to the provider's region; in a member account, set it to the hub's region."
  default     = null
}

variable "hub" {
  type = object({
    execute_remediation_role_arn = string
    check_guardrails_role_arn    = string
  })
  description = "Set in a member account, from the hub's member_account_config output. Adds the two roles the hub's Lambda functions assume to run playbooks and read resource tags here. Leave null in the hub account itself."
  default     = null
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to every role."
  default     = {}
}
