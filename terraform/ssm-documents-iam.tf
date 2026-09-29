# IAM playbooks this module owns, beyond DisableCompromisedCredentials in
# ssm-documents.tf.

# --- Stale access key deactivation ------------------------------------------
# Suggested mode: "approval_required". A key can be old and still in use,
# so a human confirms before a workload loses its credentials. Keys are
# deactivated, not deleted, so the change is reversible.

resource "aws_iam_role" "stale_keys_automation" {
  name = "${local.name_prefix}-stale-keys-automation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ssm.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "stale_keys_automation" {
  name = "${local.name_prefix}-stale-keys-automation-policy"
  role = aws_iam_role.stale_keys_automation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # The user isn't known until the automation parses the finding.
        Effect = "Allow"
        Action = [
          "iam:ListUserTags",
          "iam:ListAccessKeys",
          "iam:GetAccessKeyLastUsed",
          "iam:UpdateAccessKey",
        ]
        Resource = "${local.arn_prefix}:iam::${local.account_id}:user/*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.notifications.arn
      },
    ]
  })
}

resource "aws_ssm_document" "deactivate_stale_access_keys" {
  name            = "${local.name_prefix}-DeactivateStaleAccessKeys"
  document_type   = "Automation"
  document_format = "YAML"
  tags            = local.common_tags

  content = yamlencode({
    schemaVersion = "0.3"
    description   = "Deactivates an IAM user's access keys that are too old or unused for too long."
    assumeRole    = "{{ AutomationAssumeRole }}"
    parameters = {
      ResourceArn = {
        type        = "String"
        description = "ARN of the flagged IAM user."
      }
      FindingId = {
        type        = "String"
        description = "Security Hub finding ID, for traceability."
        default     = "unspecified"
      }
      MaxKeyAgeDays = {
        type    = "String"
        default = tostring(var.stale_key_max_age_days)
      }
      MaxUnusedDays = {
        type    = "String"
        default = tostring(var.stale_key_max_unused_days)
      }
      ExemptTagKey = {
        type        = "String"
        description = "Users with this tag key are skipped. Empty disables the exemption."
        default     = var.stale_key_exempt_tag_key
      }
      NotificationTopicArn = {
        type    = "String"
        default = aws_sns_topic.notifications.arn
      }
      AutomationAssumeRole = {
        type    = "String"
        default = aws_iam_role.stale_keys_automation.arn
      }
    }
    mainSteps = [
      {
        name   = "DeactivateStaleKeys"
        action = "aws:executeScript"
        inputs = {
          Runtime = "python3.11"
          Handler = "handler"
          InputPayload = {
            ResourceArn   = "{{ ResourceArn }}"
            MaxKeyAgeDays = "{{ MaxKeyAgeDays }}"
            MaxUnusedDays = "{{ MaxUnusedDays }}"
            ExemptTagKey  = "{{ ExemptTagKey }}"
          }
          Script = file("${path.module}/ssm-documents/scripts/deactivate_stale_access_keys.py")
        }
        outputs = [
          { Name = "UserName", Selector = "$.Payload.UserName", Type = "String" },
          { Name = "Reasons", Selector = "$.Payload.Reasons", Type = "String" },
        ]
      },
      {
        name   = "NotifyStep"
        action = "aws:executeAwsApi"
        isEnd  = true
        inputs = {
          Service  = "sns"
          Api      = "Publish"
          TopicArn = "{{ NotificationTopicArn }}"
          Subject  = "IAM user {{ DeactivateStaleKeys.UserName }} - stale access keys checked"
          Message  = <<-EOT
            Stale access key check for user {{ DeactivateStaleKeys.UserName }}
            (finding {{ FindingId }}): {{ DeactivateStaleKeys.Reasons }}.
            Deactivated keys can be re-enabled with
            aws iam update-access-key --status Active.
          EOT
        }
      },
    ]
  })
}
