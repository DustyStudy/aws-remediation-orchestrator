# Minimal HTTP API fronting approval_callback: a single GET route for the
# approve/deny links in the approval SNS notification. No auth on the
# route itself - the HMAC signature in the link is what's checked, inside
# the Lambda (see approval_callback/handler.py's docstring for the known
# limitation this implies).

resource "aws_apigatewayv2_api" "approvals" {
  name          = "${local.name_prefix}-approvals"
  protocol_type = "HTTP"
  tags          = local.common_tags
}

resource "aws_cloudwatch_log_group" "api_gateway_access_logs" {
  name              = "/aws/apigateway/${local.name_prefix}-approvals"
  retention_in_days = var.lambda_log_retention_days
  kms_key_id        = aws_kms_key.lambda.arn
}

resource "aws_apigatewayv2_stage" "approvals" {
  api_id      = aws_apigatewayv2_api.approvals.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway_access_logs.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      responseLength = "$context.responseLength"
    })
  }

  default_route_settings {
    throttling_burst_limit = 10
    throttling_rate_limit  = 5
  }

  tags = local.common_tags
}

resource "aws_apigatewayv2_integration" "approval_callback" {
  api_id                 = aws_apigatewayv2_api.approvals.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.approval_callback.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "decision" {
  # checkov:skip=CKV_AWS_309: intentionally no IAM/JWT authorizer on this
  # route - it's meant to be reachable from an email link with no signed-in
  # session behind it. approval_callback/handler.py verifies an HMAC
  # signature on the query string instead; see that file's docstring for
  # the known limitation this implies (the signature proves the link
  # wasn't tampered with, not who clicked it) and docs/ARCHITECTURE.md for
  # how to harden this further.
  api_id    = aws_apigatewayv2_api.approvals.id
  route_key = "GET /decision"
  target    = "integrations/${aws_apigatewayv2_integration.approval_callback.id}"
}

resource "aws_lambda_permission" "allow_api_gateway" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.approval_callback.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.approvals.execution_arn}/*/*/decision"
}
