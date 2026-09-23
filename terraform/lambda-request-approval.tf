data "archive_file" "request_approval" {
  type        = "zip"
  source_file = "${path.module}/lambda/request_approval/handler.py"
  output_path = "${path.module}/.build/request_approval.zip"
}

resource "aws_iam_role" "request_approval" {
  name = "${local.name_prefix}-request-approval-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "request_approval" {
  name = "${local.name_prefix}-request-approval-policy"
  role = aws_iam_role.request_approval.id

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
        Action   = ["dynamodb:PutItem"]
        Resource = aws_dynamodb_table.pending_approvals.arn
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.notifications.arn
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

resource "aws_lambda_function" "request_approval" {
  # checkov:skip=CKV_AWS_117: control-plane only, no VPC resources touched.
  # checkov:skip=CKV_AWS_116: this function is invoked synchronously
  # (by Step Functions or API Gateway, not async), so Lambda's own DLQ
  # mechanism - which only applies to failed async invocations - doesn't
  # apply. Retry/failure handling for the Step-Functions-invoked functions
  # lives in the state machine definition (Retry/Catch); API Gateway
  # surfaces a synchronous error response directly to the caller.
  function_name                  = "${local.name_prefix}-request-approval"
  description                    = "approval_required path: stashes the Step Functions task token and emails the approve/deny links. Does not itself resume the state machine."
  role                           = aws_iam_role.request_approval.arn
  handler                        = "handler.handler"
  runtime                        = "python3.12"
  timeout                        = 15
  memory_size                    = 128
  reserved_concurrent_executions = var.enable_lambda_reserved_concurrency ? 20 : null
  filename                       = data.archive_file.request_approval.output_path
  source_code_hash               = data.archive_file.request_approval.output_base64sha256
  kms_key_arn                    = aws_kms_key.lambda.arn
  code_signing_config_arn        = var.code_signing_config_arn
  layers                         = [aws_lambda_layer_version.common.arn]

  environment {
    variables = {
      PENDING_APPROVALS_TABLE_NAME = aws_dynamodb_table.pending_approvals.name
      NOTIFICATION_TOPIC_ARN       = aws_sns_topic.notifications.arn
      APPROVAL_BASE_URL            = "${aws_apigatewayv2_stage.approvals.invoke_url}/decision"
      SIGNING_SECRET_ARN           = aws_secretsmanager_secret.approval_signing_secret.arn
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "request_approval" {
  name              = "/aws/lambda/${aws_lambda_function.request_approval.function_name}"
  retention_in_days = var.lambda_log_retention_days
  kms_key_id        = aws_kms_key.lambda.arn
}
