data "archive_file" "execute_remediation" {
  type        = "zip"
  source_file = "${path.module}/lambda/execute_remediation/handler.py"
  output_path = "${path.module}/.build/execute_remediation.zip"
}

resource "aws_iam_role" "execute_remediation" {
  name = "${local.name_prefix}-execute-remediation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "execute_remediation" {
  name = "${local.name_prefix}-execute-remediation-policy"
  role = aws_iam_role.execute_remediation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${local.arn_prefix}:logs:${local.region}:${local.account_id}:*"
      },
      {
        # Start/GetAutomationExecution can be scoped to the specific
        # documents this deployment is allowed to run: the ones this
        # module owns, plus whatever's listed in
        # var.external_ssm_document_arns (e.g. aws-cloud-security-toolbox
        # playbooks). Never "run any automation document in the account".
        Effect = "Allow"
        Action = ["ssm:StartAutomationExecution"]
        Resource = concat(
          [
            aws_ssm_document.s3_public_access_remediation.arn,
            aws_ssm_document.disable_compromised_credentials.arn,
          ],
          var.external_ssm_document_arns,
        )
      },
      {
        # GetAutomationExecution addresses a specific execution ID, which
        # doesn't exist until StartAutomationExecution returns one - no
        # narrower resource is possible for the poll step.
        Effect   = "Allow"
        Action   = ["ssm:GetAutomationExecution"]
        Resource = "${local.arn_prefix}:ssm:${local.region}:${local.account_id}:automation-execution/*"
      },
      {
        # Required so SSM Automation can assume the documents' own roles
        # on this function's behalf. Scoped to the two automation roles
        # this module creates and to the ssm.amazonaws.com service only -
        # this function can never pass an arbitrary role to an arbitrary
        # service.
        Effect = "Allow"
        Action = ["iam:PassRole"]
        Resource = [
          aws_iam_role.s3_automation.arn,
          aws_iam_role.guardduty_credentials_automation.arn,
        ]
        Condition = {
          StringEquals = { "iam:PassedToService" = "ssm.amazonaws.com" }
        }
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

resource "aws_lambda_function" "execute_remediation" {
  # checkov:skip=CKV_AWS_117: control-plane only, no VPC resources touched.
  # checkov:skip=CKV_AWS_116: this function is invoked synchronously
  # (by Step Functions or API Gateway, not async), so Lambda's own DLQ
  # mechanism - which only applies to failed async invocations - doesn't
  # apply. Retry/failure handling for the Step-Functions-invoked functions
  # lives in the state machine definition (Retry/Catch); API Gateway
  # surfaces a synchronous error response directly to the caller.
  function_name                  = "${local.name_prefix}-execute-remediation"
  description                    = "Auto/approved path: starts the policy's SSM Automation document and polls it to completion."
  role                           = aws_iam_role.execute_remediation.arn
  handler                        = "handler.handler"
  runtime                        = "python3.12"
  timeout                        = 120
  memory_size                    = 128
  reserved_concurrent_executions = 20
  filename                       = data.archive_file.execute_remediation.output_path
  source_code_hash               = data.archive_file.execute_remediation.output_base64sha256
  kms_key_arn                    = aws_kms_key.lambda.arn
  code_signing_config_arn        = var.code_signing_config_arn
  layers                         = [aws_lambda_layer_version.common.arn]

  environment {
    variables = {
      POLL_TIMEOUT_SECONDS  = "90"
      POLL_INTERVAL_SECONDS = "3"
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "execute_remediation" {
  name              = "/aws/lambda/${aws_lambda_function.execute_remediation.function_name}"
  retention_in_days = var.lambda_log_retention_days
  kms_key_id        = aws_kms_key.lambda.arn
}
