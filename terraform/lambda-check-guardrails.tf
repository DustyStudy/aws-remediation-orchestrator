data "archive_file" "check_guardrails" {
  type        = "zip"
  source_file = "${path.module}/lambda/check_guardrails/handler.py"
  output_path = "${path.module}/.build/check_guardrails.zip"
}

resource "aws_iam_role" "check_guardrails" {
  name = "${local.name_prefix}-check-guardrails-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "check_guardrails" {
  name = "${local.name_prefix}-check-guardrails-policy"
  role = aws_iam_role.check_guardrails.id

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
        Action   = ["ssm:GetParameter", "ssm:PutParameter"]
        Resource = aws_ssm_parameter.pause.arn
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.rate_limit_counters.arn
      },
      {
        # GetResources (Resource Groups Tagging API) has no resource-level
        # support - it's how the denylist check works generically across
        # resource types without per-service Describe/Get calls.
        Effect   = "Allow"
        Action   = ["tag:GetResources"]
        Resource = "*"
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

resource "aws_lambda_function" "check_guardrails" {
  # checkov:skip=CKV_AWS_117: control-plane only, no VPC resources touched.
  # checkov:skip=CKV_AWS_116: this function is invoked synchronously
  # (by Step Functions or API Gateway, not async), so Lambda's own DLQ
  # mechanism - which only applies to failed async invocations - doesn't
  # apply. Retry/failure handling for the Step-Functions-invoked functions
  # lives in the state machine definition (Retry/Catch); API Gateway
  # surfaces a synchronous error response directly to the caller.
  function_name                  = "${local.name_prefix}-check-guardrails"
  description                    = "Step 3: circuit breaker, rate limit, and resource-denylist checks - see remediation_common.guardrails."
  role                           = aws_iam_role.check_guardrails.arn
  handler                        = "handler.handler"
  runtime                        = "python3.12"
  timeout                        = 15
  memory_size                    = 128
  reserved_concurrent_executions = var.enable_lambda_reserved_concurrency ? 20 : null
  filename                       = data.archive_file.check_guardrails.output_path
  source_code_hash               = data.archive_file.check_guardrails.output_base64sha256
  kms_key_arn                    = aws_kms_key.lambda.arn
  code_signing_config_arn        = var.code_signing_config_arn
  layers                         = [aws_lambda_layer_version.common.arn]

  environment {
    variables = {
      PAUSE_PARAMETER_NAME       = aws_ssm_parameter.pause.name
      PAUSE_PARAMETER_KMS_KEY_ID = aws_kms_key.data.arn
      RATE_LIMIT_TABLE_NAME      = aws_dynamodb_table.rate_limit_counters.name
      CIRCUIT_BREAKER_MULTIPLIER = "3"
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "check_guardrails" {
  name              = "/aws/lambda/${aws_lambda_function.check_guardrails.function_name}"
  retention_in_days = var.lambda_log_retention_days
  kms_key_id        = aws_kms_key.lambda.arn
}
