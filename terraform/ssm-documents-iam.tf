# IAM playbooks this module owns, beyond DisableCompromisedCredentials in
# ssm-documents.tf.

# --- Stale access key deactivation ------------------------------------------
# Suggested mode: "approval_required". A key can be old and still in use,
# so a human confirms before a workload loses its credentials. Keys are
# deactivated, not deleted, so the change is reversible.

resource "aws_ssm_document" "deactivate_stale_access_keys" {
  name            = "${local.name_prefix}-DeactivateStaleAccessKeys"
  document_type   = "Automation"
  document_format = "YAML"
  permissions     = local.document_share
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
        default = module.playbook_roles.role_arns["stale_keys_automation"]
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

# --- Role session revocation -------------------------------------------------
# Suggested mode: "approval_required". Revoking cuts off every workload
# using the role until it fetches fresh credentials, which is an outage
# if the finding is a false positive. The policy is inline and named
# AWSRevokeOlderSessions, so undoing it means deleting that one policy.

resource "aws_ssm_document" "revoke_role_sessions" {
  name            = "${local.name_prefix}-RevokeRoleSessions"
  document_type   = "Automation"
  document_format = "YAML"
  permissions     = local.document_share
  tags            = local.common_tags

  content = yamlencode({
    schemaVersion = "0.3"
    description   = "Revokes every active session of the IAM role in a GuardDuty credential finding by denying credentials issued before now."
    assumeRole    = "{{ AutomationAssumeRole }}"
    parameters = {
      ResourceArn = {
        type        = "String"
        description = "Resource ID from the finding (the access key). Kept for the common contract; the role comes from RoleName."
      }
      FindingId = {
        type        = "String"
        description = "Security Hub finding ID, used to tag the role."
        default     = "unspecified"
      }
      AccountId = {
        type        = "String"
        description = "Account from the finding. The script refuses to run if it isn't this account."
        default     = "unspecified"
      }
      RoleName = {
        type        = "String"
        description = "Name of the IAM role whose sessions to revoke."
        default     = "unspecified"
      }
      NotificationTopicArn = {
        type    = "String"
        default = aws_sns_topic.notifications.arn
      }
      AutomationAssumeRole = {
        type    = "String"
        default = module.playbook_roles.role_arns["revoke_sessions_automation"]
      }
    }
    mainSteps = [
      {
        name   = "RevokeSessions"
        action = "aws:executeScript"
        inputs = {
          Runtime = "python3.11"
          Handler = "handler"
          InputPayload = {
            RoleName  = "{{ RoleName }}"
            AccountId = "{{ AccountId }}"
            FindingId = "{{ FindingId }}"
          }
          Script = file("${path.module}/ssm-documents/scripts/revoke_role_sessions.py")
        }
        outputs = [
          { Name = "RoleArn", Selector = "$.Payload.RoleArn", Type = "String" },
          { Name = "RevokedBefore", Selector = "$.Payload.RevokedBefore", Type = "String" },
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
          Subject  = "IAM role {{ RoleName }} - active sessions revoked"
          Message  = <<-EOT
            Denied every session of {{ RevokeSessions.RoleArn }} issued before
            {{ RevokeSessions.RevokedBefore }}, in response to finding {{ FindingId }}
            (account {{ AccountId }}). New sessions still work. To undo, delete the
            role's inline policy AWSRevokeOlderSessions. If the credentials came from
            an instance, isolate it too, or new sessions can be stolen the same way.
          EOT
        }
      },
    ]
  })
}
