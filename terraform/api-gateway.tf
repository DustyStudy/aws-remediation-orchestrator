# Signed GET links only review a request. Decisions require an IAM-signed
# POST, authorized by the approver's existing role or Identity Center session.

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
  # checkov:skip=CKV_AWS_309: read-only review of an HMAC-signed link; the separate POST route requires IAM.
  api_id    = aws_apigatewayv2_api.approvals.id
  route_key = "GET /decision"
  target    = "integrations/${aws_apigatewayv2_integration.approval_callback.id}"
}

resource "aws_apigatewayv2_route" "submit_decision" {
  api_id             = aws_apigatewayv2_api.approvals.id
  route_key          = "POST /decision"
  authorization_type = "AWS_IAM"
  target             = "integrations/${aws_apigatewayv2_integration.approval_callback.id}"
}

resource "aws_lambda_permission" "allow_api_gateway" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.approval_callback.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.approvals.execution_arn}/*/*/decision"
}
