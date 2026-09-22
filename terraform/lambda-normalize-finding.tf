data "archive_file" "normalize_finding" {
  type        = "zip"
  source_file = "${path.module}/lambda/normalize_finding/handler.py"
  output_path = "${path.module}/.build/normalize_finding.zip"
}

resource "aws_iam_role" "normalize_finding" {
  name = "${local.name_prefix}-normalize-finding-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "normalize_finding" {
  name = "${local.name_prefix}-normalize-finding-policy"
  role = aws_iam_role.normalize_finding.id

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
        Action   = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource = aws_kms_key.lambda.arn
      },
      {
        Effect   = "Allow"
        Action   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
        Resource = "*"
      },
    ]
  })
}

resource "aws_lambda_function" "normalize_finding" {
  # checkov:skip=CKV_AWS_117: control-plane only, no VPC resources touched.
  # checkov:skip=CKV_AWS_116: this function is invoked synchronously
  # (by Step Functions or API Gateway, not async), so Lambda's own DLQ
  # mechanism - which only applies to failed async invocations - doesn't
  # apply. Retry/failure handling for the Step-Functions-invoked functions
  # lives in the state machine definition (Retry/Catch); API Gateway
  # surfaces a synchronous error response directly to the caller.
  # checkov:skip=CKV_AWS_173: this function takes no environment variables
  # (it's a pure ASFF parser) - nothing here for kms_key_arn to encrypt.
  # kms_key_arn is still set, and encrypts this function's log group.
  function_name                  = "${local.name_prefix}-normalize-finding"
  description                    = "Step 1: parses the raw Security Hub ASFF finding into the normalized shape the rest of the state machine uses."
  role                           = aws_iam_role.normalize_finding.arn
  handler                        = "handler.handler"
  runtime                        = "python3.12"
  timeout                        = 15
  memory_size                    = 128
  reserved_concurrent_executions = 20
  filename                       = data.archive_file.normalize_finding.output_path
  source_code_hash               = data.archive_file.normalize_finding.output_base64sha256
  kms_key_arn                    = aws_kms_key.lambda.arn
  code_signing_config_arn        = var.code_signing_config_arn
  layers                         = [aws_lambda_layer_version.common.arn]

  tracing_config {
    mode = "Active"
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "normalize_finding" {
  name              = "/aws/lambda/${aws_lambda_function.normalize_finding.function_name}"
  retention_in_days = var.lambda_log_retention_days
  kms_key_id        = aws_kms_key.lambda.arn
}
