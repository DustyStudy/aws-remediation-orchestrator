# The org-wide circuit breaker (remediation_common.guardrails). Flipping
# this to "true" - by hand, or automatically when the rate limiter
# suspects a detector storm - pauses every remediation regardless of
# policy. lifecycle.ignore_changes on value means Terraform won't fight an
# operator (or the automation itself) flipping it at runtime; only its
# existence and initial value are managed here.

resource "aws_ssm_parameter" "pause" {
  name        = "/${local.name_prefix}/paused"
  description = "Circuit breaker: \"true\" pauses all remediation execution org-wide."
  type        = "SecureString"
  key_id      = aws_kms_key.data.arn
  value       = "false"
  tags        = local.common_tags

  lifecycle {
    ignore_changes = [value]
  }
}
