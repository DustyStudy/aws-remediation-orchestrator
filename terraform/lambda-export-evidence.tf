data "archive_file" "export_evidence" {
  type        = "zip"
  source_file = "${path.module}/lambda/export_evidence/handler.py"
  output_path = "${path.module}/.build/export_evidence.zip"
}

resource "aws_iam_role" "export_evidence" {
  name = "${local.name_prefix}-export-evidence-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "export_evidence" {
  name = "${local.name_prefix}-export-evidence-policy"
  role = aws_iam_role.export_evidence.id

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
        Resource = aws_dynamodb_table.remediation_ledger.arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.evidence.arn}/remediation-orchestrator/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey*", "kms:Decrypt"]
        Resource = "*"
        Condition = {
          StringEquals = { "kms:ViaService" = "s3.${local.region}.amazonaws.com" }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = aws_sqs_queue.export_evidence_dlq.arn
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

resource "aws_lambda_function" "export_evidence" {
  # checkov:skip=CKV_AWS_117: control-plane only, no VPC resources touched.
  function_name                  = "${local.name_prefix}-export-evidence"
  description                    = "Scheduled: summarizes the period's ledger entries into grc-evidence-automation-shaped evidence documents in S3."
  role                           = aws_iam_role.export_evidence.arn
  handler                        = "handler.handler"
  runtime                        = "python3.12"
  timeout                        = 300
  memory_size                    = 256
  reserved_concurrent_executions = 1
  filename                       = data.archive_file.export_evidence.output_path
  source_code_hash               = data.archive_file.export_evidence.output_base64sha256
  kms_key_arn                    = aws_kms_key.lambda.arn
  code_signing_config_arn        = var.code_signing_config_arn
  layers                         = [aws_lambda_layer_version.common.arn]

  dead_letter_config {
    target_arn = aws_sqs_queue.export_evidence_dlq.arn
  }

  environment {
    variables = {
      LEDGER_TABLE_NAME    = aws_dynamodb_table.remediation_ledger.name
      EVIDENCE_BUCKET_NAME = aws_s3_bucket.evidence.bucket
      LOOKBACK_HOURS       = tostring(var.evidence_lookback_hours)
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "export_evidence" {
  name              = "/aws/lambda/${aws_lambda_function.export_evidence.function_name}"
  retention_in_days = var.lambda_log_retention_days
  kms_key_id        = aws_kms_key.lambda.arn
}

resource "aws_cloudwatch_event_rule" "export_evidence_schedule" {
  name                = "${local.name_prefix}-export-evidence-schedule"
  description         = "Triggers the compliance evidence export on a schedule."
  schedule_expression = var.evidence_export_schedule
}

resource "aws_cloudwatch_event_target" "export_evidence" {
  rule = aws_cloudwatch_event_rule.export_evidence_schedule.name
  arn  = aws_lambda_function.export_evidence.arn
}

resource "aws_lambda_permission" "allow_eventbridge_export_evidence" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.export_evidence.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.export_evidence_schedule.arn
}
