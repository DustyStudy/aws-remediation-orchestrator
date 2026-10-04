# Org mode: one deployment in the account that receives the organization's
# findings, running playbooks in the member accounts that own the
# resources. Off unless var.org_member_account_ids is set. See
# docs/ORG_MODE.md.
#
# The pieces: the playbook documents are shared with the member accounts
# (ssm-documents*.tf), the hub's execute_remediation and check_guardrails
# functions may assume one role each in a member, and the member's
# playbook roles may publish to the hub's notifications topic.

locals {
  org_mode = length(var.org_member_account_ids) > 0

  # modules/playbook-roles creates these under the same names.
  member_execution_role_name  = "${local.name_prefix}-member-execution-role"
  member_guardrails_role_name = "${local.name_prefix}-member-guardrails-role"

  member_account_roots           = [for id in var.org_member_account_ids : "${local.arn_prefix}:iam::${id}:root"]
  member_automation_role_pattern = "${local.arn_prefix}:iam::*:role/${local.name_prefix}-*-automation-role"

  document_share = local.org_mode ? {
    type        = "Share"
    account_ids = join(",", var.org_member_account_ids)
  } : null
}
