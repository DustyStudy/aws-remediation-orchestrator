# Each event starts one execution; its Map state processes every finding.

resource "aws_cloudwatch_event_rule" "security_hub_findings" {
  name        = "${local.name_prefix}-security-hub-findings"
  description = "Routes new/notified, active Security Hub findings to the remediation orchestrator state machine."

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        RecordState = ["ACTIVE"]
        Workflow = {
          Status = ["NEW", "NOTIFIED"]
        }
      }
    }
  })

  tags = local.common_tags
}

resource "aws_iam_role" "eventbridge_start_execution" {
  name = "${local.name_prefix}-eventbridge-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "eventbridge_start_execution" {
  name = "${local.name_prefix}-eventbridge-policy"
  role = aws_iam_role.eventbridge_start_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["states:StartExecution"]
      Resource = aws_sfn_state_machine.orchestrator.arn
    }]
  })
}

resource "aws_cloudwatch_event_target" "orchestrator" {
  rule     = aws_cloudwatch_event_rule.security_hub_findings.name
  arn      = aws_sfn_state_machine.orchestrator.arn
  role_arn = aws_iam_role.eventbridge_start_execution.arn
}
