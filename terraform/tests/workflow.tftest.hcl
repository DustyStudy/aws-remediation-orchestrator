mock_provider "aws" {
  mock_resource "aws_cloudwatch_event_rule" { defaults = { arn = "arn:aws:events:us-east-1:123456789012:rule/test" } }
  mock_resource "aws_apigatewayv2_api" { defaults = { execution_arn = "arn:aws:execute-api:us-east-1:123456789012:test" } }
  mock_resource "aws_sqs_queue" { defaults = { arn = "arn:aws:sqs:us-east-1:123456789012:test" } }
  mock_resource "aws_kms_key" { defaults = { arn = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111" } }
  mock_resource "aws_iam_role" { defaults = { arn = "arn:aws:iam::123456789012:role/test" } }
  mock_resource "aws_lambda_layer_version" { defaults = { arn = "arn:aws:lambda:us-east-1:123456789012:layer:test:1" } }
  mock_resource "aws_lambda_function" { defaults = { arn = "arn:aws:lambda:us-east-1:123456789012:function:test", invoke_arn = "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:test/invocations" } }
  mock_resource "aws_cloudwatch_log_group" { defaults = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:test" } }
  mock_resource "aws_sns_topic" { defaults = { arn = "arn:aws:sns:us-east-1:123456789012:test" } }
  mock_resource "aws_sfn_state_machine" { defaults = { arn = "arn:aws:states:us-east-1:123456789012:stateMachine:test" } }
  mock_resource "aws_secretsmanager_secret" { defaults = { arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-abcdef" } }
  mock_resource "aws_ssm_document" { defaults = { arn = "arn:aws:ssm:us-east-1:123456789012:document/test" } }
  mock_resource "aws_s3_bucket" { defaults = { arn = "arn:aws:s3:::test-evidence", id = "test-evidence" } }
  mock_data "aws_partition" { defaults = { partition = "aws", dns_suffix = "amazonaws.com" } }
  mock_data "aws_region" { defaults = { region = "us-east-1", name = "us-east-1" } }
  mock_data "aws_caller_identity" { defaults = { account_id = "123456789012" } }
}
mock_provider "archive" {}
mock_provider "random" {}

variables {
  policy_registry_seed = {
    default = { match_field = "type_prefix", match_value = "", mode = "dry_run", description = "Test default" }
  }
}

run "workflow_contract" {
  command = apply
  assert {
    condition     = jsondecode(aws_sfn_state_machine.orchestrator.definition).States.ProcessFindings.ItemsPath == "$.findings" && jsondecode(aws_sfn_state_machine.orchestrator.definition).States.ProcessFindings.MaxConcurrency == 5
    error_message = "Every normalized finding must enter the bounded Map."
  }
  assert {
    condition = alltrue([
      for name in ["LookupPolicy", "CheckGuardrails", "RequestApproval"] :
      contains([for catcher in jsondecode(aws_sfn_state_machine.orchestrator.definition).States.ProcessFindings.ItemProcessor.States[name].Catch : catcher.Next], "RecordPipelineFailed")
    ])
    error_message = "Policy, guardrail, and approval failures must have a ledger path."
  }
  assert {
    condition     = aws_apigatewayv2_route.submit_decision.authorization_type == "AWS_IAM" && aws_apigatewayv2_route.submit_decision.route_key == "POST /decision"
    error_message = "Only an IAM-authenticated POST may submit decisions."
  }
  assert {
    condition = alltrue([
      for name, state in jsondecode(aws_sfn_state_machine.orchestrator.definition).States.ProcessFindings.ItemProcessor.States :
      state.Parameters["timestamp.$"] == "$$.State.EnteredTime" && length(state.Retry) > 0
      if startswith(name, "Record")
    ])
    error_message = "Ledger retries must preserve the event timestamp."
  }
  assert {
    condition     = jsondecode(aws_sfn_state_machine.orchestrator.definition).States.ProcessFindings.ItemProcessor.States.ApprovalDecision.Choices[1].Next == "SetDeniedByHuman"
    error_message = "A structured denial must never reach remediation."
  }
  assert {
    condition     = length(aws_cloudwatch_metric_alarm.execution_failed) == 3
    error_message = "Workflow failures, timeouts, and aborts need independent alarms."
  }
  assert {
    condition = (
      jsondecode(aws_sfn_state_machine.orchestrator.definition).States.ProcessFindings.ItemProcessor.States.SetDecidedByHumanApproved.Next == "RecheckGuardrails" &&
      jsondecode(aws_sfn_state_machine.orchestrator.definition).States.ProcessFindings.ItemProcessor.States.RecheckGuardrails.Parameters.recheck == true &&
      jsondecode(aws_sfn_state_machine.orchestrator.definition).States.ProcessFindings.ItemProcessor.States.RecheckGuardrails.Catch[0].Next == "RecordPipelineFailed" &&
      jsondecode(aws_sfn_state_machine.orchestrator.definition).States.ProcessFindings.ItemProcessor.States.RecheckChoice.Choices[0].BooleanEquals == true &&
      jsondecode(aws_sfn_state_machine.orchestrator.definition).States.ProcessFindings.ItemProcessor.States.RecheckChoice.Choices[0].Next == "ExecuteRemediation" &&
      jsondecode(aws_sfn_state_machine.orchestrator.definition).States.ProcessFindings.ItemProcessor.States.RecheckChoice.Default == "RecordBlockedAfterApproval"
    )
    error_message = "An approved remediation must pass the circuit breaker and denylist again, failing closed, before it runs."
  }
  assert {
    condition = length([
      for name, state in jsondecode(aws_sfn_state_machine.orchestrator.definition).States.ProcessFindings.ItemProcessor.States :
      name if try(state.Next, "") == "ExecuteRemediation" || anytrue([for c in try(state.Choices, []) : c.Next == "ExecuteRemediation"])
    ]) == 2
    error_message = "Only the auto path and the post-approval recheck may lead to remediation."
  }
  assert {
    condition = alltrue(concat(
      [for state in [jsondecode(aws_sfn_state_machine.orchestrator.definition).States.NormalizeFinding] :
      state.Retry[0].ErrorEquals == ["Lambda.TooManyRequestsException"] && state.Retry[0].MaxAttempts >= 10],
      [for name, state in jsondecode(aws_sfn_state_machine.orchestrator.definition).States.ProcessFindings.ItemProcessor.States :
        state.Retry[0].ErrorEquals == ["Lambda.TooManyRequestsException"] && state.Retry[0].MaxAttempts >= 10 && state.Retry[0].JitterStrategy == "FULL"
      if state.Type == "Task"]
    ))
    error_message = "Every Lambda task must retry throttling first, for several minutes with jitter, so a finding burst is not dropped."
  }
  assert {
    condition     = jsondecode(aws_sfn_state_machine.orchestrator.definition).TimeoutSeconds == 86400 + 7200
    error_message = "Executions need an overall time limit, or the ExecutionsTimedOut alarm can never fire."
  }
  assert {
    condition = (
      jsondecode(aws_cloudwatch_event_rule.execution_timed_out.event_pattern).source == ["aws.states"] &&
      jsondecode(aws_cloudwatch_event_rule.execution_timed_out.event_pattern).detail.status == ["TIMED_OUT"] &&
      jsondecode(aws_cloudwatch_event_rule.execution_timed_out.event_pattern).detail.stateMachineArn == [aws_sfn_state_machine.orchestrator.arn] &&
      aws_cloudwatch_event_target.record_timeout.arn == aws_lambda_function.record_timeout.arn &&
      aws_lambda_function.record_timeout.environment[0].variables.STATE_MACHINE_ARN == aws_sfn_state_machine.orchestrator.arn &&
      aws_lambda_function.record_timeout.dead_letter_config[0].target_arn == aws_sns_topic.notifications.arn
    )
    error_message = "A timed-out execution runs no catch state, so its findings must reach the ledger through record_timeout, and a failed recording must notify."
  }
  assert {
    condition     = aws_lambda_function.request_approval.environment[0].variables.APPROVAL_TIMEOUT_SECONDS == "86400"
    error_message = "The approval message must state the configured timeout."
  }
}

run "approval_timeout_cannot_outlive_the_link" {
  command = plan
  variables {
    approval_timeout_seconds = 90000
  }
  expect_failures = [var.approval_timeout_seconds]
}

run "execution_timeout_can_be_set" {
  command = plan
  variables {
    approval_timeout_seconds  = 600
    execution_timeout_seconds = 4200
  }
  assert {
    condition     = jsondecode(aws_sfn_state_machine.orchestrator.definition).TimeoutSeconds == 4200
    error_message = "An explicit execution_timeout_seconds must reach the state machine."
  }
}

run "execution_timeout_must_outlast_the_approval" {
  command = plan
  variables {
    approval_timeout_seconds  = 86400
    execution_timeout_seconds = 4000
  }
  expect_failures = [aws_sfn_state_machine.orchestrator]
}

run "execution_timeout_rejects_too_short_values" {
  command = plan
  variables {
    execution_timeout_seconds = 60
  }
  expect_failures = [var.execution_timeout_seconds]
}
