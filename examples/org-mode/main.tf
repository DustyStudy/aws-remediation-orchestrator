# Org mode: one orchestrator in the account that receives the
# organization's findings (the Security Hub delegated administrator),
# remediating in two member accounts. See docs/ORG_MODE.md.
#
# Each account gets its own provider. Add a provider and a
# "member_<name>" module block per extra member account, and its ID to
# member_account_ids. In a large organization, apply
# terraform/modules/playbook-roles from your account baseline pipeline
# instead of listing accounts here.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

variable "region" {
  type        = string
  description = "Region the orchestrator runs in. Playbooks run in this region in every account."
}

variable "hub_profile" {
  type        = string
  description = "AWS CLI profile for the hub account."
}

variable "member_a_profile" {
  type        = string
  description = "AWS CLI profile for the first member account."
}

variable "member_b_profile" {
  type        = string
  description = "AWS CLI profile for the second member account."
}

variable "member_account_ids" {
  type        = list(string)
  description = "Account IDs of the member accounts above."
}

variable "notification_email" {
  type        = string
  description = "Receives approval requests and results."
}

variable "policy_registry_seed" {
  type        = any
  description = "Passed to the orchestrator. See terraform/terraform.tfvars.example."
}

variable "enable_lambda_reserved_concurrency" {
  type        = bool
  description = "Set false in an account whose Lambda concurrency limit is under ~150."
  default     = true
}

variable "evidence_bucket_force_destroy" {
  type        = bool
  description = "Set true for a deployment you intend to tear down."
  default     = false
}

provider "aws" {
  region  = var.region
  profile = var.hub_profile
}

provider "aws" {
  alias   = "member_a"
  region  = var.region
  profile = var.member_a_profile
}

provider "aws" {
  alias   = "member_b"
  region  = var.region
  profile = var.member_b_profile
}

module "orchestrator" {
  source = "../../terraform"

  notification_email                 = var.notification_email
  policy_registry_seed               = var.policy_registry_seed
  org_member_account_ids             = var.member_account_ids
  enable_lambda_reserved_concurrency = var.enable_lambda_reserved_concurrency
  evidence_bucket_force_destroy      = var.evidence_bucket_force_destroy
}

module "member_a" {
  source    = "../../terraform/modules/playbook-roles"
  providers = { aws = aws.member_a }

  name_prefix            = module.orchestrator.member_account_config.name_prefix
  region                 = module.orchestrator.member_account_config.region
  notification_topic_arn = module.orchestrator.member_account_config.notification_topic_arn
  data_key_arn           = module.orchestrator.member_account_config.data_key_arn
  hub                    = module.orchestrator.member_account_config.hub
}

module "member_b" {
  source    = "../../terraform/modules/playbook-roles"
  providers = { aws = aws.member_b }

  name_prefix            = module.orchestrator.member_account_config.name_prefix
  region                 = module.orchestrator.member_account_config.region
  notification_topic_arn = module.orchestrator.member_account_config.notification_topic_arn
  data_key_arn           = module.orchestrator.member_account_config.data_key_arn
  hub                    = module.orchestrator.member_account_config.hub
}

output "orchestrator" {
  value = {
    state_machine_arn      = module.orchestrator.state_machine_arn
    ledger_table           = module.orchestrator.remediation_ledger_table_name
    evidence_bucket        = module.orchestrator.evidence_bucket_name
    circuit_breaker_param  = module.orchestrator.circuit_breaker_parameter_name
    notification_topic_arn = module.orchestrator.notification_topic_arn
  }
  description = "What live_test.py and an operator need from the hub."
}
