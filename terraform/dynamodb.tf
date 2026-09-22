# --- policy-registry --------------------------------------------------
# Small, hand-seeded table (see var.policy_registry_seed / variables.tf).
# lookup_policy.handler scans it in full on every finding; that's fine at
# the size this table is meant to stay - a few dozen playbook rules, not
# a per-resource database.

resource "aws_dynamodb_table" "policy_registry" {
  name         = "${local.name_prefix}-policy-registry"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "match_id"

  attribute {
    name = "match_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.data.arn
  }

  tags = local.common_tags
}

resource "aws_dynamodb_table_item" "policy_registry_seed" {
  for_each = var.policy_registry_seed

  table_name = aws_dynamodb_table.policy_registry.name
  hash_key   = aws_dynamodb_table.policy_registry.hash_key

  item = jsonencode({
    match_id              = { S = each.key }
    match_field           = { S = each.value.match_field }
    match_value           = { S = each.value.match_value }
    mode                  = { S = each.value.mode }
    action_document       = { S = each.value.action_document }
    action_document_owner = { S = each.value.action_document_owner }
    nist_controls         = { L = [for c in each.value.nist_controls : { S = c }] }
    max_actions_per_hour  = { N = tostring(each.value.max_actions_per_hour) }
    severity_threshold    = each.value.severity_threshold == null ? { NULL = true } : { S = each.value.severity_threshold }
    description           = { S = each.value.description }
  })
}

# --- rate-limit-counters ------------------------------------------------
# One item per (policy_id, hour-bucket), incremented atomically by
# check_guardrails.handler. TTL cleans up counters two hours after their
# bucket - see remediation_common.guardrails.check_rate_limit.

resource "aws_dynamodb_table" "rate_limit_counters" {
  # checkov:skip=CKV_AWS_28: point-in-time recovery is for data worth
  # restoring - these items are hour-bucketed counters that self-expire
  # via TTL within two hours and are fully reconstructible from the
  # ledger. Restoring stale rate-limit counters would be actively wrong.
  name         = "${local.name_prefix}-rate-limit-counters"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "counter_key"

  attribute {
    name = "counter_key"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.data.arn
  }

  tags = local.common_tags
}

# --- pending-approvals ---------------------------------------------------
# One item per outstanding approval-required remediation, holding the Step
# Functions task token until approval_callback.handler resolves it. TTL
# matches var.approval_timeout_seconds so an abandoned request cleans
# itself up around the same time the Step Functions task itself times out.

resource "aws_dynamodb_table" "pending_approvals" {
  name         = "${local.name_prefix}-pending-approvals"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "approval_id"

  attribute {
    name = "approval_id"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.data.arn
  }

  tags = local.common_tags
}

# --- remediation-ledger ---------------------------------------------------
# The audit trail: one item per state-machine execution outcome. Never
# expires (no TTL) - this is compliance evidence, not a cache - and keeps
# point-in-time recovery on since it's the thing export_evidence.handler
# and any future compliance tooling reads from.

resource "aws_dynamodb_table" "remediation_ledger" {
  name         = "${local.name_prefix}-remediation-ledger"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"
  range_key    = "execution_ts"

  attribute {
    name = "finding_id"
    type = "S"
  }

  attribute {
    name = "execution_ts"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.data.arn
  }

  tags = local.common_tags
}
