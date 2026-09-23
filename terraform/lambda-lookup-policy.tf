data "archive_file" "lookup_policy" {
  type        = "zip"
  source_file = "${path.module}/lambda/lookup_policy/handler.py"
  output_path = "${path.module}/.build/lookup_policy.zip"
}

resource "aws_iam_role" "lookup_policy" {
  name = "${local.name_prefix}-lookup-policy-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lookup_policy" {
  name = "${local.name_prefix}-lookup-policy-policy"
  role = aws_iam_role.lookup_policy.id

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
        Action   = ["dynamodb:Scan"]
        Resource = aws_dynamodb_table.policy_registry.arn
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

resource "aws_lambda_function" "lookup_policy" {
  # checkov:skip=CKV_AWS_117: control-plane only, no VPC resources touched.
  # checkov:skip=CKV_AWS_116: this function is invoked synchronously
  # (by Step Functions or API Gateway, not async), so Lambda's own DLQ
  # mechanism - which only applies to failed async invocations - doesn't
  # apply. Retry/failure handling for the Step-Functions-invoked functions
  # lives in the state machine definition (Retry/Catch); API Gateway
  # surfaces a synchronous error response directly to the caller.
  function_name                  = "${local.name_prefix}-lookup-policy"
  description                    = "Step 2: matches the normalized finding against the policy registry and applies its severity floor."
  role                           = aws_iam_role.lookup_policy.arn
  handler                        = "handler.handler"
  runtime                        = "python3.12"
  timeout                        = 15
  memory_size                    = 128
  reserved_concurrent_executions = var.enable_lambda_reserved_concurrency ? 20 : null
  filename                       = data.archive_file.lookup_policy.output_path
  source_code_hash               = data.archive_file.lookup_policy.output_base64sha256
  kms_key_arn                    = aws_kms_key.lambda.arn
  code_signing_config_arn        = var.code_signing_config_arn
  layers                         = [aws_lambda_layer_version.common.arn]

  environment {
    variables = {
      POLICY_TABLE_NAME = aws_dynamodb_table.policy_registry.name
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "lookup_policy" {
  name              = "/aws/lambda/${aws_lambda_function.lookup_policy.function_name}"
  retention_in_days = var.lambda_log_retention_days
  kms_key_id        = aws_kms_key.lambda.arn
}
