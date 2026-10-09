# Independent of the ledger Lambda: failures remain visible during a ledger outage.
resource "aws_cloudwatch_metric_alarm" "execution_failed" {
  for_each            = toset(["ExecutionsFailed", "ExecutionsTimedOut", "ExecutionsAborted"])
  alarm_name          = "${local.name_prefix}-${each.key}"
  alarm_description   = "Inspect execution history and reconcile the ledger before replaying."
  namespace           = "AWS/States"
  metric_name         = each.key
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  dimensions          = { StateMachineArn = aws_sfn_state_machine.orchestrator.arn }
  alarm_actions       = [aws_sns_topic.notifications.arn]
  tags                = local.common_tags
}
