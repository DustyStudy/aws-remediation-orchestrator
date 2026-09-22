# Shared infrastructure across every Lambda function in this module: the
# CMK that encrypts log groups + environment variables, the layer
# packaging remediation_common (see terraform/lambda/common/), and the DLQ
# for the one asynchronously-invoked function (export_evidence - invoked
# by EventBridge, not by Step Functions, so it's the only one where a
# Lambda-level DLQ is the right mechanism; the Step-Functions-invoked
# functions rely on Retry/Catch in the state machine definition instead).

resource "aws_kms_key" "lambda" {
  description         = "Encrypts ${local.name_prefix} Lambda log groups and environment variables."
  enable_key_rotation = true

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
      {
        Sid       = "AllowCloudWatchLogsUseOfKey"
        Effect    = "Allow"
        Principal = { Service = "logs.${local.region}.amazonaws.com" }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*",
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "${local.arn_prefix}:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${local.name_prefix}-*"
          }
        }
      },
      {
        Sid       = "AllowSQSUseOfKey"
        Effect    = "Allow"
        Principal = { Service = "sqs.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:Decrypt"]
        Resource  = "*"
        Condition = {
          StringEquals = { "kms:CallerAccount" = local.account_id }
        }
      },
    ]
  })
}

resource "aws_kms_alias" "lambda" {
  name          = "alias/${local.name_prefix}-lambda"
  target_key_id = aws_kms_key.lambda.key_id
}

resource "aws_sqs_queue" "export_evidence_dlq" {
  name                      = "${local.name_prefix}-export-evidence-dlq"
  kms_master_key_id         = aws_kms_key.lambda.arn
  message_retention_seconds = 1209600
  tags                      = local.common_tags
}

data "archive_file" "common_layer" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/common"
  output_path = "${path.module}/.build/common-layer.zip"
}

resource "aws_lambda_layer_version" "common" {
  layer_name          = "${local.name_prefix}-common"
  filename            = data.archive_file.common_layer.output_path
  source_code_hash    = data.archive_file.common_layer.output_base64sha256
  compatible_runtimes = ["python3.12"]
  description         = "remediation_common: ASFF parsing, policy matching, guardrails, ledger/evidence building - shared by every function in this module."
}
