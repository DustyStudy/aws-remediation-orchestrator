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

locals {
  playbook_document_names = [
    aws_ssm_document.s3_public_access_remediation.name,
    aws_ssm_document.disable_compromised_credentials.name,
    aws_ssm_document.revoke_open_ssh_rdp.name,
    aws_ssm_document.isolate_compromised_instance.name,
    aws_ssm_document.deactivate_stale_access_keys.name,
    aws_ssm_document.revoke_role_sessions.name,
  ]
}

resource "aws_iam_role_policy" "execute_remediation" {
  name = "${local.name_prefix}-execute-remediation-policy"
  role = aws_iam_role.execute_remediation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${local.arn_prefix}:logs:${local.region}:${local.account_id}:*"
      },
      {
        # StartAutomationExecution is scoped to the specific documents
        # this deployment is allowed to run: the ones this module owns,
        # plus whatever's listed in var.external_ssm_document_arns. Never
        # "run any automation document in the account". SSM authorizes
        # the call against the document ARN, and the service reference
        # also lists the automation definition, so both forms are named.
        Effect = "Allow"
        Action = ["ssm:StartAutomationExecution"]
        Resource = concat(
          [for name in local.playbook_document_names : "${local.arn_prefix}:ssm:${local.region}:${local.account_id}:document/${name}"],
          [for name in local.playbook_document_names : "${local.arn_prefix}:ssm:${local.region}:${local.account_id}:automation-definition/${name}:*"],
          var.external_ssm_document_arns,
        )
      },
      {
        # StartAutomationExecution is also authorized against the
        # execution it is about to create, and GetAutomationExecution
        # addresses that execution by ID. Neither ID exists beforehand,
        # so no narrower resource is possible. The statement above still
        # limits which documents can be started.
        Effect   = "Allow"
        Action   = ["ssm:StartAutomationExecution", "ssm:GetAutomationExecution"]
        Resource = "${local.arn_prefix}:ssm:${local.region}:${local.account_id}:automation-execution/*"
      },
      {
        # Required so SSM Automation can assume the documents' own roles
        # on this function's behalf. Scoped to the automation roles
        # this module creates and to the ssm.amazonaws.com service only -
        # this function can never pass an arbitrary role to an arbitrary
        # service.
        Effect = "Allow"
        Action = ["iam:PassRole"]
        Resource = [
          module.playbook_roles.role_arns["s3_automation"],
          module.playbook_roles.role_arns["guardduty_credentials_automation"],
          module.playbook_roles.role_arns["sg_automation"],
          module.playbook_roles.role_arns["isolation_automation"],
          module.playbook_roles.role_arns["stale_keys_automation"],
          module.playbook_roles.role_arns["revoke_sessions_automation"],
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
      ], local.org_mode ? [
      {
        # Org mode: run a playbook in a member account through the role
        # modules/playbook-roles creates there.
        Effect   = "Allow"
        Action   = ["sts:AssumeRole"]
        Resource = [for id in var.org_member_account_ids : "${local.arn_prefix}:iam::${id}:role/${local.member_execution_role_name}"]
      },
      {
        # To read a playbook's default automation role, whose name is the
        # same in every account.
        Effect   = "Allow"
        Action   = ["ssm:DescribeDocument"]
        Resource = ["${local.arn_prefix}:ssm:${local.region}:${local.account_id}:document/${local.name_prefix}-*"]
      },
    ] : [])
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
  reserved_concurrent_executions = var.enable_lambda_reserved_concurrency ? 20 : null
  filename                       = data.archive_file.execute_remediation.output_path
  source_code_hash               = data.archive_file.execute_remediation.output_base64sha256
  kms_key_arn                    = aws_kms_key.lambda.arn
  code_signing_config_arn        = var.code_signing_config_arn
  layers                         = [aws_lambda_layer_version.common.arn]

  environment {
    variables = {
      POLL_TIMEOUT_SECONDS  = "90"
      POLL_INTERVAL_SECONDS = "3"
      # Empty outside org mode, which keeps every playbook in this account.
      MEMBER_EXECUTION_ROLE_NAME = local.org_mode ? local.member_execution_role_name : ""
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
