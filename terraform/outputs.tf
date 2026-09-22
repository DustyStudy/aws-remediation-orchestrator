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
  value       = "${aws_apigatewayv2_stage.approvals.invoke_url}/decision"
  description = "The approve/deny callback URL embedded in approval-request notifications."
}
