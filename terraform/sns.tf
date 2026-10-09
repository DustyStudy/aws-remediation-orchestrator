resource "aws_sns_topic" "notifications" {
  name              = "${local.name_prefix}-notifications"
  kms_master_key_id = aws_kms_key.data.arn
  tags              = local.common_tags
}

resource "aws_sns_topic_policy" "notifications" {
  arn = aws_sns_topic.notifications.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([{
      Sid       = "AllowAccountPublish"
      Effect    = "Allow"
      Principal = { AWS = "${local.arn_prefix}:iam::${local.account_id}:root" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.notifications.arn
      }, {
      Sid       = "AllowWorkflowAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.notifications.arn
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account_id }
        ArnLike      = { "aws:SourceArn" = "${local.arn_prefix}:cloudwatch:${local.region}:${local.account_id}:alarm:${local.name_prefix}-Executions*" }
      }
      }], local.org_mode ? [{
      # Org mode: playbooks running in a member account report here too.
      Sid       = "AllowMemberPlaybookPublish"
      Effect    = "Allow"
      Principal = { AWS = local.member_account_roots }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.notifications.arn
      Condition = {
        ArnLike = { "aws:PrincipalArn" = local.member_automation_role_pattern }
      }
    }] : [])
  })
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.notifications.arn
  protocol  = "email"
  endpoint  = var.notification_email
}
