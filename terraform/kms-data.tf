# Customer-managed key for data at rest: the four DynamoDB tables, the
# approval-signing secret, the circuit-breaker SSM parameter, the evidence
# bucket and the notifications topic. Kept
# separate from aws_kms_key.lambda (lambda-common.tf), which is scoped to
# log/environment-variable encryption - different blast radius, different
# key policy needs.

resource "aws_kms_key" "data" {
  description             = "Encrypts ${local.name_prefix} DynamoDB tables, secrets, evidence bucket and notifications topic."
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid       = "EnableIAMUserPermissions"
        Effect    = "Allow"
        Principal = { AWS = "${local.arn_prefix}:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowWorkflowAlarms"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = local.account_id }
          ArnLike      = { "aws:SourceArn" = "${local.arn_prefix}:cloudwatch:${local.region}:${local.account_id}:alarm:${local.name_prefix}-Executions*" }
        }
      },
      ], local.org_mode ? [
      {
        # Org mode: a member account's playbook roles publish to the
        # notifications topic, which this key encrypts.
        Sid       = "AllowMemberPlaybookNotify"
        Effect    = "Allow"
        Principal = { AWS = local.member_account_roots }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource  = "*"
        Condition = {
          ArnLike = { "aws:PrincipalArn" = local.member_automation_role_pattern }
        }
      },
    ] : [])
  })
}

resource "aws_kms_alias" "data" {
  name          = "alias/${local.name_prefix}-data"
  target_key_id = aws_kms_key.data.key_id
}
