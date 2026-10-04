output "state_machine_arn" {
  value       = aws_sfn_state_machine.orchestrator.arn
  description = "ARN of the orchestration state machine, for cross-stack references or manual test executions."
}

output "notification_topic_arn" {
  value       = aws_sns_topic.notifications.arn
  description = "SNS topic every ledger entry and approval request is published to. Subscribe Slack/PagerDuty/etc. here in addition to, or instead of, notification_email."
}

output "policy_registry_table_name" {
  value       = aws_dynamodb_table.policy_registry.name
  description = "DynamoDB table name for the policy registry, for adding/editing playbook rules outside of Terraform (e.g. a break-glass policy change) - see docs/POLICY_REGISTRY.md."
}

output "remediation_ledger_table_name" {
  value       = aws_dynamodb_table.remediation_ledger.name
  description = "DynamoDB table name for the audit ledger."
}

output "evidence_bucket_name" {
  value       = aws_s3_bucket.evidence.bucket
  description = "S3 bucket export_evidence writes grc-evidence-automation-shaped compliance evidence documents to."
}

output "circuit_breaker_parameter_name" {
  value       = aws_ssm_parameter.pause.name
  description = "SSM parameter name for the org-wide circuit breaker. Set to \"true\" to pause all remediation execution."
}

output "approvals_endpoint" {
  value       = "${trimsuffix(aws_apigatewayv2_stage.approvals.invoke_url, "/")}/decision"
  description = "The approve/deny callback URL embedded in approval-request notifications."
}

output "playbook_document_names" {
  value = {
    s3_public_access_remediation    = aws_ssm_document.s3_public_access_remediation.name
    disable_compromised_credentials = aws_ssm_document.disable_compromised_credentials.name
    revoke_open_ssh_rdp             = aws_ssm_document.revoke_open_ssh_rdp.name
    isolate_compromised_instance    = aws_ssm_document.isolate_compromised_instance.name
    deactivate_stale_access_keys    = aws_ssm_document.deactivate_stale_access_keys.name
    revoke_role_sessions            = aws_ssm_document.revoke_role_sessions.name
  }
  description = "SSM Automation document names of the playbooks this module owns, for a policy item's action_document."
}

output "member_account_config" {
  value = {
    name_prefix            = local.name_prefix
    region                 = local.region
    notification_topic_arn = aws_sns_topic.notifications.arn
    data_key_arn           = aws_kms_key.data.arn
    hub = {
      execute_remediation_role_arn = aws_iam_role.execute_remediation.arn
      check_guardrails_role_arn    = aws_iam_role.check_guardrails.arn
    }
  }
  description = "Inputs for modules/playbook-roles in a member account (org mode). Each key is that module's variable of the same name."
}

output "wiz_webhook_url_base" {
  value       = one(module.wiz_finding_bridge[*].webhook_url_base)
  description = "Base URL of the Wiz webhook endpoint, or null when enable_wiz_finding_bridge is false. See modules/wiz-finding-bridge/README.md for building the full URL."
}

output "wiz_webhook_secret_arn" {
  value       = one(module.wiz_finding_bridge[*].webhook_secret_arn)
  description = "Secrets Manager secret holding the Wiz webhook path token, or null when the bridge is off."
}
