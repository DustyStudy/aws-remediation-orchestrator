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
}
