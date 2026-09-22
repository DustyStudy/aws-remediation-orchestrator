# The orchestration engine itself. See docs/ARCHITECTURE.md for the full
# flow diagram; in short: normalize -> match policy -> check guardrails ->
# route on mode (ignore/dry_run/approval_required/auto) -> execute ->
# record. Every path - including the ones that never touch AWS resources
# at all (skipped, blocked, denied) - ends in RecordLedger, so the ledger
# is a complete record of every decision this system ever made, not just
# the ones that took action.

resource "aws_cloudwatch_log_group" "state_machine" {
  name              = "/aws/vendedlogs/states/${local.name_prefix}"
  retention_in_days = var.lambda_log_retention_days
  kms_key_id        = aws_kms_key.lambda.arn
}

resource "aws_iam_role" "state_machine" {
  name = "${local.name_prefix}-state-machine-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "states.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "state_machine" {
  name = "${local.name_prefix}-state-machine-policy"
  role = aws_iam_role.state_machine.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["lambda:InvokeFunction"]
        Resource = [
          aws_lambda_function.normalize_finding.arn,
          aws_lambda_function.lookup_policy.arn,
          aws_lambda_function.check_guardrails.arn,
          aws_lambda_function.execute_remediation.arn,
          aws_lambda_function.request_approval.arn,
          aws_lambda_function.record_ledger.arn,
        ]
      },
      {
        # Required for the state machine's logging_configuration; none of
        # these actions support resource-level scoping (AWS-documented
        # requirement for Step Functions -> CloudWatch Logs delivery).
        Effect = "Allow"
        Action = [
          "logs:CreateLogDelivery",
          "logs:GetLogDelivery",
          "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:ListLogDeliveries",
          "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies",
          "logs:DescribeLogGroups",
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets"]
        Resource = "*"
      },
    ]
  })
}

resource "aws_sfn_state_machine" "orchestrator" {
  name     = local.name_prefix
  role_arn = aws_iam_role.state_machine.arn
  type     = "STANDARD" # not EXPRESS: executions can wait on human approval for up to approval_timeout_seconds, and the full execution history matters for audit review.

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.state_machine.arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }

  tracing_configuration {
    enabled = true
  }

  definition = jsonencode({
    Comment = "Routes a Security Hub finding through policy matching, guardrails, and (auto/approved/dry-run) remediation."
    StartAt = "NormalizeFinding"
    States = {
      NormalizeFinding = {
        Type     = "Task"
        Resource = aws_lambda_function.normalize_finding.arn
        Retry    = [{ ErrorEquals = ["Lambda.ServiceException", "Lambda.TooManyRequestsException"], IntervalSeconds = 2, MaxAttempts = 3, BackoffRate = 2 }]
        Next     = "CheckSkip"
      }
      CheckSkip = {
        Type = "Choice"
        Choices = [
          { Variable = "$.skip", BooleanEquals = true, Next = "CheckHasFinding" },
        ]
        Default = "LookupPolicy"
      }
      CheckHasFinding = {
        Type = "Choice"
        Choices = [
          { Variable = "$.finding", IsPresent = true, Next = "RecordSkipped" },
        ]
        Default = "NothingToDo"
      }
      NothingToDo = { Type = "Succeed" }
      RecordSkipped = {
        Type     = "Task"
        Resource = aws_lambda_function.record_ledger.arn
        Parameters = {
          "finding.$" = "$.finding"
          outcome     = "skipped"
          decided_by  = "system"
        }
        End = true
      }
      LookupPolicy = {
        Type     = "Task"
        Resource = aws_lambda_function.lookup_policy.arn
        Parameters = {
          "finding.$" = "$.finding"
        }
        Retry = [{ ErrorEquals = ["Lambda.ServiceException", "Lambda.TooManyRequestsException"], IntervalSeconds = 2, MaxAttempts = 3, BackoffRate = 2 }]
        Next  = "CheckGuardrails"
      }
      CheckGuardrails = {
        Type     = "Task"
        Resource = aws_lambda_function.check_guardrails.arn
        Parameters = {
          "finding.$" = "$.finding"
          "policy.$"  = "$.policy"
        }
        Retry = [{ ErrorEquals = ["Lambda.ServiceException", "Lambda.TooManyRequestsException"], IntervalSeconds = 2, MaxAttempts = 3, BackoffRate = 2 }]
        Next  = "GuardrailChoice"
      }
      GuardrailChoice = {
        Type = "Choice"
        Choices = [
          { Variable = "$.guardrail_result.allowed", BooleanEquals = false, Next = "RecordBlocked" },
        ]
        Default = "ModeChoice"
      }
      RecordBlocked = {
        Type     = "Task"
        Resource = aws_lambda_function.record_ledger.arn
        Parameters = {
          "finding.$"          = "$.finding"
          "policy.$"           = "$.policy"
          "guardrail_result.$" = "$.guardrail_result"
          outcome              = "blocked"
          decided_by           = "system"
        }
        End = true
      }
      ModeChoice = {
        Type = "Choice"
        Choices = [
          { Variable = "$.policy.mode", StringEquals = "ignore", Next = "RecordIgnored" },
          { Variable = "$.policy.mode", StringEquals = "dry_run", Next = "RecordDryRun" },
          { Variable = "$.policy.mode", StringEquals = "approval_required", Next = "RequestApproval" },
          { Variable = "$.policy.mode", StringEquals = "auto", Next = "SetDecidedBySystem" },
        ]
        Default = "RecordIgnored" # unrecognized mode - fail closed to no-op, never to auto-execute.
      }
      RecordIgnored = {
        Type     = "Task"
        Resource = aws_lambda_function.record_ledger.arn
        Parameters = {
          "finding.$"          = "$.finding"
          "policy.$"           = "$.policy"
          "guardrail_result.$" = "$.guardrail_result"
          outcome              = "skipped"
          decided_by           = "system"
        }
        End = true
      }
      RecordDryRun = {
        Type     = "Task"
        Resource = aws_lambda_function.record_ledger.arn
        Parameters = {
          "finding.$"          = "$.finding"
          "policy.$"           = "$.policy"
          "guardrail_result.$" = "$.guardrail_result"
          outcome              = "dry_run"
          decided_by           = "system"
        }
        End = true
      }
      RequestApproval = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::lambda:invoke.waitForTaskToken"
        Parameters = {
          FunctionName = aws_lambda_function.request_approval.arn
          Payload = {
            "finding.$"    = "$.finding"
            "policy.$"     = "$.policy"
            "task_token.$" = "$$.Task.Token"
          }
        }
        TimeoutSeconds = var.approval_timeout_seconds
        ResultPath     = "$.approval_result"
        Catch = [
          { ErrorEquals = ["States.Timeout"], ResultPath = "$.error", Next = "SetDeniedByTimeout" },
          { ErrorEquals = ["ApprovalDenied"], ResultPath = "$.error", Next = "SetDeniedByHuman" },
        ]
        Next = "SetDecidedByHumanApproved"
      }
      SetDeniedByTimeout = {
        Type       = "Pass"
        Result     = "system (approval timed out)"
        ResultPath = "$.decided_by"
        Next       = "RecordDenied"
      }
      SetDeniedByHuman = {
        Type       = "Pass"
        Result     = "human (approval link)"
        ResultPath = "$.decided_by"
        Next       = "RecordDenied"
      }
      RecordDenied = {
        Type     = "Task"
        Resource = aws_lambda_function.record_ledger.arn
        Parameters = {
          "finding.$"          = "$.finding"
          "policy.$"           = "$.policy"
          "guardrail_result.$" = "$.guardrail_result"
          outcome              = "denied"
          "decided_by.$"       = "$.decided_by"
        }
        End = true
      }
      SetDecidedByHumanApproved = {
        Type       = "Pass"
        Result     = "human (approval link)"
        ResultPath = "$.decided_by"
        Next       = "ExecuteRemediation"
      }
      SetDecidedBySystem = {
        Type       = "Pass"
        Result     = "system"
        ResultPath = "$.decided_by"
        Next       = "ExecuteRemediation"
      }
      ExecuteRemediation = {
        Type     = "Task"
        Resource = aws_lambda_function.execute_remediation.arn
        Parameters = {
          "finding.$" = "$.finding"
          "policy.$"  = "$.policy"
        }
        ResultPath = "$.exec"
        Retry      = [{ ErrorEquals = ["Lambda.ServiceException", "Lambda.TooManyRequestsException"], IntervalSeconds = 2, MaxAttempts = 3, BackoffRate = 2 }]
        Catch = [
          { ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "RecordExecutionFailed" },
        ]
        Next = "RecordExecuted"
      }
      RecordExecuted = {
        Type     = "Task"
        Resource = aws_lambda_function.record_ledger.arn
        Parameters = {
          "finding.$"          = "$.finding"
          "policy.$"           = "$.policy"
          "guardrail_result.$" = "$.guardrail_result"
          "outcome.$"          = "$.exec.outcome"
          "decided_by.$"       = "$.decided_by"
          "execution_id.$"     = "$.exec.execution_id"
          "execution_status.$" = "$.exec.execution_status"
        }
        End = true
      }
      RecordExecutionFailed = {
        Type     = "Task"
        Resource = aws_lambda_function.record_ledger.arn
        Parameters = {
          "finding.$"          = "$.finding"
          "policy.$"           = "$.policy"
          "guardrail_result.$" = "$.guardrail_result"
          outcome              = "failed"
          "decided_by.$"       = "$.decided_by"
        }
        End = true
      }
    }
  })

  tags = local.common_tags
}
