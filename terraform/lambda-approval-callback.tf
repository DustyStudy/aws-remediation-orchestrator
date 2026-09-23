data "archive_file" "approval_callback" {
  type        = "zip"
  source_file = "${path.module}/lambda/approval_callback/handler.py"
  output_path = "${path.module}/.build/approval_callback.zip"
}

resource "aws_iam_role" "approval_callback" {
  name = "${local.name_prefix}-approval-callback-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "approval_callback" {
  name = "${local.name_prefix}-approval-callback-policy"
  role = aws_iam_role.approval_callback.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${local.arn_prefix}:logs:${local.region}:${local.account_id}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.pending_approvals.arn
      },
      {
        # SendTaskSuccess/Failure address a task by its token, not an ARN -
        # IAM has no resource-level scoping for these actions.
        Effect   = "Allow"
        Action   = ["states:SendTaskSuccess", "states:SendTaskFailure"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.approval_signing_secret.arn
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource = [aws_kms_key.lambda.arn, aws_kms_key.data.arn]
      },
      {
        Effect   = "Allow"
        Action   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
        Resource = "*"
      },
    ]
  })
}

resource "aws_lambda_function" "approval_callback" {
  # checkov:skip=CKV_AWS_117: control-plane only, no VPC resources touched.
  # checkov:skip=CKV_AWS_116: this function is invoked synchronously
  # (by Step Functions or API Gateway, not async), so Lambda's own DLQ
  # mechanism - which only applies to failed async invocations - doesn't
  # apply. Retry/failure handling for the Step-Functions-invoked functions
  # lives in the state machine definition (Retry/Catch); API Gateway
  # surfaces a synchronous error response directly to the caller.
  function_name                  = "${local.name_prefix}-approval-callback"
  description                    = "API Gateway target for the approve/deny links: verifies the signature and resolves the waiting Step Functions task."
  role                           = aws_iam_role.approval_callback.arn
  handler                        = "handler.handler"
  runtime                        = "python3.12"
  timeout                        = 15
  memory_size                    = 128
  reserved_concurrent_executions = var.enable_lambda_reserved_concurrency ? 10 : null
  filename                       = data.archive_file.approval_callback.output_path
  source_code_hash               = data.archive_file.approval_callback.output_base64sha256
  kms_key_arn                    = aws_kms_key.lambda.arn
  code_signing_config_arn        = var.code_signing_config_arn
  layers                         = [aws_lambda_layer_version.common.arn]

  environment {
    variables = {
      PENDING_APPROVALS_TABLE_NAME = aws_dynamodb_table.pending_approvals.name
      SIGNING_SECRET_ARN           = aws_secretsmanager_secret.approval_signing_secret.arn
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "approval_callback" {
  name              = "/aws/lambda/${aws_lambda_function.approval_callback.function_name}"
  retention_in_days = var.lambda_log_retention_days
  kms_key_id        = aws_kms_key.lambda.arn
}
