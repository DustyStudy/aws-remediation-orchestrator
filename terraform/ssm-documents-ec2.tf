# EC2 playbooks this module owns. Like ssm-documents.tf, every document
# takes ResourceArn and FindingId, which is all execute_remediation passes,
# and gives every other parameter a default.

# --- Open SSH/RDP revocation -------------------------------------------------
# Suggested mode: "auto". Revoking an internet-wide 22/3389 rule can only
# reduce exposure, and running it twice is a no-op. Rules from narrower
# CIDRs are left alone.

resource "aws_iam_role" "sg_automation" {
  name = "${local.name_prefix}-sg-automation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ssm.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "sg_automation" {
  name = "${local.name_prefix}-sg-automation-policy"
  role = aws_iam_role.sg_automation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
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
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.notifications.arn
      },
      {
        # The notifications topic is encrypted with the data key.
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource = aws_kms_key.data.arn
      },
    ]
  })
}

resource "aws_ssm_document" "revoke_open_ssh_rdp" {
  name            = "${local.name_prefix}-RevokeOpenSshRdpIngress"
  document_type   = "Automation"
  document_format = "YAML"
  tags            = local.common_tags

  content = yamlencode({
    schemaVersion = "0.3"
    description   = "Revokes security group ingress rules that open a risky port (SSH, RDP and database ports by default) to 0.0.0.0/0 or ::/0."
    assumeRole    = "{{ AutomationAssumeRole }}"
    parameters = {
      ResourceArn = {
        type        = "String"
        description = "ARN of the flagged security group."
      }
      RiskyPorts = {
        type        = "String"
        description = "Comma-separated ports. An internet-wide ingress rule that covers any of them is revoked."
        default     = join(",", var.open_ingress_revoke_ports)
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
        default = aws_iam_role.sg_automation.arn
      }
    }
    mainSteps = [
      {
        name   = "RevokeOpenIngress"
        action = "aws:executeScript"
        inputs = {
          Runtime      = "python3.11"
          Handler      = "handler"
          InputPayload = { ResourceArn = "{{ ResourceArn }}", RiskyPorts = "{{ RiskyPorts }}" }
          Script       = file("${path.module}/ssm-documents/scripts/revoke_open_ssh_rdp.py")
        }
        outputs = [
          { Name = "GroupId", Selector = "$.Payload.GroupId", Type = "String" },
          { Name = "RevokedRules", Selector = "$.Payload.RevokedRules", Type = "String" },
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
          Subject  = "Security group {{ RevokeOpenIngress.GroupId }} - internet-wide ingress revoked"
          Message  = <<-EOT
            Revoked these internet-wide ingress rules (ports {{ RiskyPorts }}) on security group
            {{ RevokeOpenIngress.GroupId }} in response to finding {{ FindingId }}:
            {{ RevokeOpenIngress.RevokedRules }}
          EOT
        }
      },
    ]
  })
}

# --- Compromised instance isolation -----------------------------------------
# Suggested mode: "approval_required". Isolation cuts every connection to
# the instance, which is an outage if the finding is a false positive.

resource "aws_iam_role" "isolation_automation" {
  name = "${local.name_prefix}-isolation-automation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ssm.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "isolation_automation" {
  name = "${local.name_prefix}-isolation-automation-policy"
  role = aws_iam_role.isolation_automation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
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
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.notifications.arn
      },
      {
        # The notifications topic is encrypted with the data key.
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource = aws_kms_key.data.arn
      },
    ]
  })
}

resource "aws_ssm_document" "isolate_compromised_instance" {
  name            = "${local.name_prefix}-IsolateCompromisedInstance"
  document_type   = "Automation"
  document_format = "YAML"
  tags            = local.common_tags

  content = yamlencode({
    schemaVersion = "0.3"
    description   = "Snapshots and network-isolates an EC2 instance flagged by a finding, and optionally stops it."
    assumeRole    = "{{ AutomationAssumeRole }}"
    parameters = {
      ResourceArn = {
        type        = "String"
        description = "ARN of the flagged EC2 instance."
      }
      FindingId = {
        type        = "String"
        description = "Security Hub finding ID, used to tag the instance and snapshots."
        default     = "unspecified"
      }
      StopInstance = {
        type          = "String"
        description   = "Also stop the instance, which ends connections the security group change doesn't."
        default       = var.isolation_stop_instance ? "true" : "false"
        allowedValues = ["true", "false"]
      }
      NamePrefix = {
        type        = "String"
        description = "Prefix for the per-VPC isolation security group name."
        default     = local.name_prefix
      }
      NotificationTopicArn = {
        type    = "String"
        default = aws_sns_topic.notifications.arn
      }
      AutomationAssumeRole = {
        type    = "String"
        default = aws_iam_role.isolation_automation.arn
      }
    }
    mainSteps = [
      {
        name   = "IsolateInstance"
        action = "aws:executeScript"
        inputs = {
          Runtime = "python3.11"
          Handler = "handler"
          InputPayload = {
            ResourceArn = "{{ ResourceArn }}"
            FindingId   = "{{ FindingId }}"
            NamePrefix  = "{{ NamePrefix }}"
          }
          Script = file("${path.module}/ssm-documents/scripts/isolate_instance.py")
        }
        outputs = [
          { Name = "InstanceId", Selector = "$.Payload.InstanceId", Type = "String" },
          { Name = "IsolationSecurityGroupId", Selector = "$.Payload.IsolationSecurityGroupId", Type = "String" },
          { Name = "SnapshotIds", Selector = "$.Payload.SnapshotIds", Type = "StringList" },
        ]
      },
      {
        name   = "CheckIfShouldStop"
        action = "aws:branch"
        inputs = {
          Choices = [
            { NextStep = "StopInstanceStep", Variable = "{{ StopInstance }}", StringEquals = "true" }
          ]
          Default = "NotifyStep"
        }
      },
      {
        name   = "StopInstanceStep"
        action = "aws:executeAwsApi"
        inputs = {
          Service     = "ec2"
          Api         = "StopInstances"
          InstanceIds = ["{{ IsolateInstance.InstanceId }}"]
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
          Subject  = "EC2 instance {{ IsolateInstance.InstanceId }} isolated"
          Message  = <<-EOT
            Instance {{ IsolateInstance.InstanceId }} was tagged, its volumes were
            snapshotted ({{ IsolateInstance.SnapshotIds }}), and every network
            interface now uses isolation security group
            {{ IsolateInstance.IsolationSecurityGroupId }}. StopInstance was
            {{ StopInstance }}. Finding: {{ FindingId }}.
          EOT
        }
      },
    ]
  })
}
