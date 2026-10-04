# The IAM roles the playbooks run as: one per SSM Automation document, each
# assumable only by ssm.amazonaws.com.
#
# The root module applies this in its own account. In org mode it is also
# applied in every member account (with var.hub set), so a playbook started
# there runs with exactly the permissions it has in the hub. Role names are
# the same in every account: the hub finds a member's automation role by
# swapping the account ID in its own role's ARN.

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  name_prefix = var.name_prefix
  account_id  = data.aws_caller_identity.current.account_id
  region      = coalesce(var.region, data.aws_region.current.region)
  arn_prefix  = "arn:${data.aws_partition.current.partition}"

  ssm_assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ssm.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  # Every playbook ends by publishing to the notifications topic, which is
  # encrypted with the data key.
  notify_statements = [
    {
      Effect   = "Allow"
      Action   = ["sns:Publish"]
      Resource = var.notification_topic_arn
    },
    {
      Effect   = "Allow"
      Action   = ["kms:Decrypt", "kms:GenerateDataKey*"]
      Resource = var.data_key_arn
    },
  ]
}

# --- S3 public access remediation ---------------------------------------

resource "aws_iam_role" "s3_automation" {
  name               = "${local.name_prefix}-s3-automation-role"
  assume_role_policy = local.ssm_assume_role_policy
  tags               = var.tags
}

resource "aws_iam_role_policy" "s3_automation" {
  name = "${local.name_prefix}-s3-automation-policy"
  role = aws_iam_role.s3_automation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        # The bucket name isn't known until the automation runs (it's
        # parsed from the finding at execution time), so this can't be
        # scoped tighter than the S3 resource type.
        Effect   = "Allow"
        Action   = ["s3:PutBucketPublicAccessBlock"]
        Resource = "${local.arn_prefix}:s3:::*"
      },
    ], local.notify_statements)
  })
}

# --- GuardDuty compromised-credential response ---------------------------

resource "aws_iam_role" "guardduty_credentials_automation" {
  name               = "${local.name_prefix}-credentials-automation-role"
  assume_role_policy = local.ssm_assume_role_policy
  tags               = var.tags
}

resource "aws_iam_role_policy" "guardduty_credentials_automation" {
  name = "${local.name_prefix}-credentials-automation-policy"
  role = aws_iam_role.guardduty_credentials_automation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
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
    ], local.notify_statements)
  })
}

# --- Open SSH/RDP revocation -------------------------------------------------

resource "aws_iam_role" "sg_automation" {
  name               = "${local.name_prefix}-sg-automation-role"
  assume_role_policy = local.ssm_assume_role_policy
  tags               = var.tags
}

resource "aws_iam_role_policy" "sg_automation" {
  name = "${local.name_prefix}-sg-automation-policy"
  role = aws_iam_role.sg_automation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        # Describe calls don't support resource-level permissions.
        Effect   = "Allow"
        Action   = ["ec2:DescribeSecurityGroups"]
        Resource = "*"
      },
      {
        # The group isn't known until the automation parses the finding.
        Effect   = "Allow"
        Action   = ["ec2:RevokeSecurityGroupIngress"]
        Resource = "${local.arn_prefix}:ec2:${local.region}:${local.account_id}:security-group/*"
      },
    ], local.notify_statements)
  })
}

# --- Compromised instance isolation -----------------------------------------

resource "aws_iam_role" "isolation_automation" {
  name               = "${local.name_prefix}-isolation-automation-role"
  assume_role_policy = local.ssm_assume_role_policy
  tags               = var.tags
}

resource "aws_iam_role_policy" "isolation_automation" {
  name = "${local.name_prefix}-isolation-automation-policy"
  role = aws_iam_role.isolation_automation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        # Describe calls don't support resource-level permissions.
        Effect   = "Allow"
        Action   = ["ec2:DescribeInstances", "ec2:DescribeSecurityGroups"]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = ["ec2:CreateTags"]
        Resource = [
          "${local.arn_prefix}:ec2:${local.region}:${local.account_id}:instance/*",
          "${local.arn_prefix}:ec2:${local.region}:${local.account_id}:security-group/*",
          "${local.arn_prefix}:ec2:${local.region}::snapshot/*",
        ]
      },
      {
        Effect = "Allow"
        Action = ["ec2:CreateSnapshot"]
        Resource = [
          "${local.arn_prefix}:ec2:${local.region}:${local.account_id}:volume/*",
          "${local.arn_prefix}:ec2:${local.region}::snapshot/*",
        ]
      },
      {
        Effect = "Allow"
        Action = ["ec2:CreateSecurityGroup"]
        Resource = [
          "${local.arn_prefix}:ec2:${local.region}:${local.account_id}:security-group/*",
          "${local.arn_prefix}:ec2:${local.region}:${local.account_id}:vpc/*",
        ]
      },
      {
        # Only on the isolation groups this playbook creates (tagged at
        # creation), so it can't strip egress from any other group.
        Effect   = "Allow"
        Action   = ["ec2:RevokeSecurityGroupEgress"]
        Resource = "${local.arn_prefix}:ec2:${local.region}:${local.account_id}:security-group/*"
        Condition = {
          StringEquals = { "aws:ResourceTag/Purpose" = "incident-response-isolation" }
        }
      },
      {
        Effect = "Allow"
        Action = ["ec2:ModifyNetworkInterfaceAttribute"]
        Resource = [
          "${local.arn_prefix}:ec2:${local.region}:${local.account_id}:network-interface/*",
          "${local.arn_prefix}:ec2:${local.region}:${local.account_id}:security-group/*",
          "${local.arn_prefix}:ec2:${local.region}:${local.account_id}:instance/*",
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["ec2:StopInstances"]
        Resource = "${local.arn_prefix}:ec2:${local.region}:${local.account_id}:instance/*"
      },
    ], local.notify_statements)
  })
}

# --- Stale access key deactivation ------------------------------------------

resource "aws_iam_role" "stale_keys_automation" {
  name               = "${local.name_prefix}-stale-keys-automation-role"
  assume_role_policy = local.ssm_assume_role_policy
  tags               = var.tags
}

resource "aws_iam_role_policy" "stale_keys_automation" {
  name = "${local.name_prefix}-stale-keys-automation-policy"
  role = aws_iam_role.stale_keys_automation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
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
    ], local.notify_statements)
  })
}

# --- Role session revocation -------------------------------------------------

resource "aws_iam_role" "revoke_sessions_automation" {
  name               = "${local.name_prefix}-revoke-sessions-automation-role"
  assume_role_policy = local.ssm_assume_role_policy
  tags               = var.tags
}

resource "aws_iam_role_policy" "revoke_sessions_automation" {
  name = "${local.name_prefix}-revoke-sessions-automation-policy"
  role = aws_iam_role.revoke_sessions_automation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        # The role isn't known until the automation parses the finding.
        # PutRolePolicy on any role is a strong grant. It's bounded by who
        # can reach this role (ssm.amazonaws.com, via this document only)
        # and by the script, which only writes the fixed deny policy.
        Effect   = "Allow"
        Action   = ["iam:GetRole", "iam:PutRolePolicy", "iam:TagRole"]
        Resource = "${local.arn_prefix}:iam::${local.account_id}:role/*"
      },
      {
        # Never let a finding revoke this module's own roles, which would
        # stop the orchestrator from running any playbook.
        Effect   = "Deny"
        Action   = ["iam:PutRolePolicy", "iam:TagRole"]
        Resource = "${local.arn_prefix}:iam::${local.account_id}:role/${local.name_prefix}-*"
      },
    ], local.notify_statements)
  })
}

# --- Org mode: roles the hub's Lambda functions assume -----------------------
# Created only in member accounts (var.hub set). Each trusts one hub
# function's role and nothing else. The trust names the hub account and
# checks the role ARN in a condition, so it keeps working if the hub role
# is ever deleted and recreated.

locals {
  hub_account_id = var.hub == null ? "" : split(":", var.hub.execute_remediation_role_arn)[4]

  member_roles = var.hub == null ? {} : {
    execution  = var.hub.execute_remediation_role_arn
    guardrails = var.hub.check_guardrails_role_arn
  }
}

resource "aws_iam_role" "member" {
  for_each = local.member_roles

  name = "${local.name_prefix}-member-${each.key}-role"
  tags = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "${local.arn_prefix}:iam::${local.hub_account_id}:root" }
      Action    = "sts:AssumeRole"
      Condition = {
        ArnEquals = { "aws:PrincipalArn" = each.value }
      }
    }]
  })
}

resource "aws_iam_role_policy" "member_execution" {
  count = var.hub == null ? 0 : 1

  name = "${local.name_prefix}-member-execution-policy"
  role = aws_iam_role.member["execution"].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Only the playbooks the hub shares with this account. Starting a
        # shared document is authorized against the owner's document ARN;
        # the automation definition forms are named too because the
        # service reference lists them for this action.
        Effect = "Allow"
        Action = ["ssm:StartAutomationExecution"]
        Resource = [
          "${local.arn_prefix}:ssm:${local.region}:${local.hub_account_id}:document/${local.name_prefix}-*",
          "${local.arn_prefix}:ssm:${local.region}:${local.hub_account_id}:automation-definition/${local.name_prefix}-*:*",
          "${local.arn_prefix}:ssm:${local.region}:${local.account_id}:automation-definition/${local.name_prefix}-*:*",
        ]
      },
      {
        # StartAutomationExecution is also authorized against the
        # execution it creates here, and the poll addresses it by ID.
        # Neither ID exists beforehand. The statement above still limits
        # which documents can be started.
        Effect   = "Allow"
        Action   = ["ssm:StartAutomationExecution", "ssm:GetAutomationExecution"]
        Resource = "${local.arn_prefix}:ssm:${local.region}:${local.account_id}:automation-execution/*"
      },
      {
        Effect = "Allow"
        Action = ["iam:PassRole"]
        Resource = [
          aws_iam_role.s3_automation.arn,
          aws_iam_role.guardduty_credentials_automation.arn,
          aws_iam_role.sg_automation.arn,
          aws_iam_role.isolation_automation.arn,
          aws_iam_role.stale_keys_automation.arn,
          aws_iam_role.revoke_sessions_automation.arn,
        ]
        Condition = {
          StringEquals = { "iam:PassedToService" = "ssm.amazonaws.com" }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy" "member_guardrails" {
  count = var.hub == null ? 0 : 1

  name = "${local.name_prefix}-member-guardrails-policy"
  role = aws_iam_role.member["guardrails"].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      # The do-not-remediate tag check. GetResources has no resource-level
      # support.
      Effect   = "Allow"
      Action   = ["tag:GetResources"]
      Resource = "*"
    }]
  })
}
