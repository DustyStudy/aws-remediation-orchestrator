output "webhook_url_base" {
  description = <<-EOT
    Base invoke URL for this API. The full webhook URL to paste into Wiz
    is this value + "/wiz-webhook/" + the secret from
    webhook_secret_arn (see the module README for the retrieval command).
  EOT
  value       = aws_apigatewayv2_api.wiz_webhook.api_endpoint
}

output "webhook_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the webhook path token."
  value       = aws_secretsmanager_secret.webhook_secret.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic used for bridged notifications."
  value       = aws_sns_topic.audit.arn
}
