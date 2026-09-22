# Playbooks this module owns outright (as opposed to ones referenced via
# var.external_ssm_document_arns). Document names must keep the exact
# suffixes execute_remediation.handler._document_parameters() matches on
# ("S3PublicAccessRemediation", "DisableCompromisedCredentials") - see
# docs/POLICY_REGISTRY.md for how a policy item's action_document ties
# back to these.

# --- S3 public access remediation ---------------------------------------
# Default mode in the seeded policy registry is "auto": re-applying Block
# Public Access is safe and idempotent - it can't make a bucket more
# exposed, and running it twice is a no-op.

resource "aws_iam_role" "s3_automation" {
  name = "${local.name_prefix}-s3-automation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ssm.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "s3_automation" {
  name = "${local.name_prefix}-s3-automation-policy"
  role = aws_iam_role.s3_automation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # The bucket name isn't known until the automation runs (it's
        # parsed from the finding at execution time), so this can't be
        # scoped tighter than the S3 resource type.
        Effect   = "Allow"
        Action   = ["s3:PutBucketPublicAccessBlock"]
        Resource = "${local.arn_prefix}:s3:::*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.notifications.arn
      },
    ]
  })
}

resource "aws_ssm_document" "s3_public_access_remediation" {
  name            = "${local.name_prefix}-S3PublicAccessRemediation"
  document_type   = "Automation"
  document_format = "YAML"
  tags            = local.common_tags

  content = yamlencode({
    schemaVersion = "0.3"
    description   = "Re-applies S3 Block Public Access on a bucket flagged by a Security Hub/Config finding."
    assumeRole    = "{{ AutomationAssumeRole }}"
    parameters = {
      ResourceArn = {
        type        = "String"
        description = "ARN of the flagged S3 bucket."
      }
      FindingId = {
        type        = "String"
        description = "Security Hub finding ID, for traceability."
        default     = "unspecified"
      }
      NotificationTopicArn = {
        type    = "String"
        default = aws_sns_topic.notifications.arn
      }
      AutomationAssumeRole = {
        type    = "String"
        default = aws_iam_role.s3_automation.arn
      }
    }
    mainSteps = [
      {
        name   = "ExtractBucketName"
        action = "aws:executeScript"
        inputs = {
          Runtime      = "python3.11"
          Handler      = "handler"
          InputPayload = { ResourceArn = "{{ ResourceArn }}" }
          Script       = file("${path.module}/ssm-documents/scripts/extract_bucket_name.py")
        }
        outputs = [
          { Name = "BucketName", Selector = "$.Payload.BucketName", Type = "String" }
        ]
      },
      {
        name   = "PutPublicAccessBlock"
        action = "aws:executeAwsApi"
        inputs = {
          Service = "s3"
          Api     = "PutPublicAccessBlock"
          Bucket  = "{{ ExtractBucketName.BucketName }}"
          PublicAccessBlockConfiguration = {
            BlockPublicAcls       = true
            IgnorePublicAcls      = true
            BlockPublicPolicy     = true
            RestrictPublicBuckets = true
          }
        }
      },
      {
        name   = "NotifyStep"
        action = "aws:executeAwsApi"
        isEnd  = true
        inputs = {
          Service  = "sns"
          Api      = "Publish"
          TopicArn = "{{ NotificationTopicArn }}"
          Subject  = "S3 bucket {{ ExtractBucketName.BucketName }} - public access blocked"
          Message  = <<-EOT
            Block Public Access was re-applied to bucket
            {{ ExtractBucketName.BucketName }} in response to finding
            {{ FindingId }}.
          EOT
        }
      },
    ]
  })
}

# --- GuardDuty compromised-credential response ---------------------------
# Default mode in the seeded policy registry is "approval_required":
# deactivating a user's keys is disruptive if the finding turns out to be
# a false positive, so a human confirms first.

resource "aws_iam_role" "guardduty_credentials_automation" {
  name = "${local.name_prefix}-credentials-automation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ssm.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "guardduty_credentials_automation" {
  name = "${local.name_prefix}-credentials-automation-policy"
  role = aws_iam_role.guardduty_credentials_automation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # The IAM user isn't known until the automation runs (it's parsed
        # from the finding at execution time), so this can't be scoped
        # tighter than the resource type - same constraint as the S3
        # automation role's PutBucketPublicAccessBlock above. The blast
        # radius this grants (deactivating any IAM user's access keys) is
        # bounded by who can reach this role: it's assumable only by
        # ssm.amazonaws.com, only via this document, and this playbook's
        # seeded mode is approval_required, so a human confirms the target
        # before it ever runs.
        Effect   = "Allow"
        Action   = ["iam:ListAccessKeys", "iam:UpdateAccessKey", "iam:TagUser"]
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

resource "aws_ssm_document" "disable_compromised_credentials" {
  name            = "${local.name_prefix}-DisableCompromisedCredentials"
  document_type   = "Automation"
  document_format = "YAML"
  tags            = local.common_tags

  content = yamlencode({
    schemaVersion = "0.3"
    description   = "Deactivates every active access key for an IAM user flagged by a GuardDuty UnauthorizedAccess:IAMUser finding."
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
      AccountId = {
        type    = "String"
        default = "unspecified"
      }
      NotificationTopicArn = {
        type    = "String"
        default = aws_sns_topic.notifications.arn
      }
      AutomationAssumeRole = {
        type    = "String"
        default = aws_iam_role.guardduty_credentials_automation.arn
      }
    }
    mainSteps = [
      {
        name   = "DisableAllAccessKeys"
        action = "aws:executeScript"
        inputs = {
          Runtime = "python3.11"
          Handler = "handler"
          InputPayload = {
            ResourceArn = "{{ ResourceArn }}"
            FindingId   = "{{ FindingId }}"
          }
          Script = file("${path.module}/ssm-documents/scripts/disable_access_keys.py")
        }
        outputs = [
          { Name = "UserName", Selector = "$.Payload.UserName", Type = "String" },
          { Name = "DisabledAccessKeyIds", Selector = "$.Payload.DisabledAccessKeyIds", Type = "StringList" },
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
          Subject  = "IAM user {{ DisableAllAccessKeys.UserName }} - access keys deactivated"
          Message  = <<-EOT
            Deactivated access key(s) {{ DisableAllAccessKeys.DisabledAccessKeyIds }}
            for user {{ DisableAllAccessKeys.UserName }} in response to finding
            {{ FindingId }} (account {{ AccountId }}). Keys were deactivated, not
            deleted, so this is reversible if the finding is a false positive.
          EOT
        }
      },
    ]
  })
}
