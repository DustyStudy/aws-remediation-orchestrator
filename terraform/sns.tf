resource "aws_sns_topic" "notifications" {
  name              = "${local.name_prefix}-notifications"
  kms_master_key_id = "alias/aws/sns"
  tags              = local.common_tags
}

resource "aws_sns_topic_policy" "notifications" {
  arn = aws_sns_topic.notifications.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowAccountPublish"
      Effect    = "Allow"
      Principal = { AWS = "${local.arn_prefix}:iam::${local.account_id}:root" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.notifications.arn
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.notifications.arn
  protocol  = "email"
  endpoint  = var.notification_email
}
