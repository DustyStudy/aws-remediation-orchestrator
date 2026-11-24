# A timed-out execution runs no catch state, so the findings it was still
# processing would have no ledger item. Step Functions emits a status change
# event when an execution times out; this function records those findings
# as timed_out.

data "archive_file" "record_timeout" {
  type        = "zip"
  source_file = "${path.module}/lambda/record_timeout/handler.py"
  output_path = "${path.module}/.build/record_timeout.zip"
}

resource "aws_iam_role" "record_timeout" {
  name = "${local.name_prefix}-record-timeout-role"

  assume_role_policy = local.lambda_assume_role_policy
}

resource "aws_iam_role_policy" "record_timeout" {
  name = "${local.name_prefix}-record-timeout-policy"
  role = aws_iam_role.record_timeout.id

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
        Action   = ["dynamodb:Query", "dynamodb:PutItem"]
        Resource = aws_dynamodb_table.remediation_ledger.arn
      },
      {
        # Only for inputs too large for the status change event.
        Effect   = "Allow"
        Action   = ["states:DescribeExecution"]
        Resource = "${local.arn_prefix}:states:${local.region}:${local.account_id}:execution:${aws_sfn_state_machine.orchestrator.name}:*"
      },
      {
        # Dead-letter target: a failed recording reaches the operators.
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.notifications.arn
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

resource "aws_lambda_function" "record_timeout" {
  # checkov:skip=CKV_AWS_117: control-plane only, no VPC resources touched.
  function_name                  = "${local.name_prefix}-record-timeout"
  description                    = "Writes a timed_out ledger item for each finding a timed-out execution left unrecorded."
  role                           = aws_iam_role.record_timeout.arn
  handler                        = "handler.handler"
  runtime                        = "python3.12"
  timeout                        = 60
  memory_size                    = 128
  reserved_concurrent_executions = var.enable_lambda_reserved_concurrency ? 2 : null
  filename                       = data.archive_file.record_timeout.output_path
  source_code_hash               = data.archive_file.record_timeout.output_base64sha256
  kms_key_arn                    = aws_kms_key.lambda.arn
  code_signing_config_arn        = var.code_signing_config_arn
  layers                         = [aws_lambda_layer_version.common.arn]

  # Invoked asynchronously by EventBridge. After Lambda's own retries, the
  # event goes to the notifications topic, so an unrecorded timeout is seen.
  dead_letter_config {
    target_arn = aws_sns_topic.notifications.arn
  }

  environment {
    variables = {
      LEDGER_TABLE_NAME = aws_dynamodb_table.remediation_ledger.name
      STATE_MACHINE_ARN = aws_sfn_state_machine.orchestrator.arn
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "record_timeout" {
  name              = "/aws/lambda/${aws_lambda_function.record_timeout.function_name}"
  retention_in_days = var.lambda_log_retention_days
  kms_key_id        = aws_kms_key.lambda.arn
}

resource "aws_cloudwatch_event_rule" "execution_timed_out" {
  name        = "${local.name_prefix}-execution-timed-out"
  description = "Records the findings of a timed-out orchestrator execution in the ledger."

  event_pattern = jsonencode({
    source      = ["aws.states"]
    detail-type = ["Step Functions Execution Status Change"]
    detail = {
      status          = ["TIMED_OUT"]
      stateMachineArn = [aws_sfn_state_machine.orchestrator.arn]
    }
  })

  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "record_timeout" {
  rule = aws_cloudwatch_event_rule.execution_timed_out.name
  arn  = aws_lambda_function.record_timeout.arn
}

resource "aws_lambda_permission" "allow_eventbridge_record_timeout" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.record_timeout.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.execution_timed_out.arn
}
