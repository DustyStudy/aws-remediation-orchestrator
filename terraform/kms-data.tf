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
    Statement = [
      {
        Sid       = "EnableIAMUserPermissions"
        Effect    = "Allow"
        Principal = { AWS = "${local.arn_prefix}:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
    ]
  })
}

resource "aws_kms_alias" "data" {
  name          = "alias/${local.name_prefix}-data"
  target_key_id = aws_kms_key.data.key_id
}
