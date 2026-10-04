output "role_arns" {
  value = {
    s3_automation                    = aws_iam_role.s3_automation.arn
    guardduty_credentials_automation = aws_iam_role.guardduty_credentials_automation.arn
    sg_automation                    = aws_iam_role.sg_automation.arn
    isolation_automation             = aws_iam_role.isolation_automation.arn
    stale_keys_automation            = aws_iam_role.stale_keys_automation.arn
    revoke_sessions_automation       = aws_iam_role.revoke_sessions_automation.arn
  }
  description = "ARN of each playbook's automation role."
}
