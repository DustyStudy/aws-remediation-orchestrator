# The roles the playbooks run as live in a module so a member account can
# get exactly the same ones (org mode, see org-mode.tf).

module "playbook_roles" {
  source = "./modules/playbook-roles"

  name_prefix            = local.name_prefix
  notification_topic_arn = aws_sns_topic.notifications.arn
  data_key_arn           = aws_kms_key.data.arn
}

# These roles were root-module resources through v1.1.0.

moved {
  from = aws_iam_role.s3_automation
  to   = module.playbook_roles.aws_iam_role.s3_automation
}

moved {
  from = aws_iam_role_policy.s3_automation
  to   = module.playbook_roles.aws_iam_role_policy.s3_automation
}

moved {
  from = aws_iam_role.guardduty_credentials_automation
  to   = module.playbook_roles.aws_iam_role.guardduty_credentials_automation
}

moved {
  from = aws_iam_role_policy.guardduty_credentials_automation
  to   = module.playbook_roles.aws_iam_role_policy.guardduty_credentials_automation
}

moved {
  from = aws_iam_role.sg_automation
  to   = module.playbook_roles.aws_iam_role.sg_automation
}

moved {
  from = aws_iam_role_policy.sg_automation
  to   = module.playbook_roles.aws_iam_role_policy.sg_automation
}

moved {
  from = aws_iam_role.isolation_automation
  to   = module.playbook_roles.aws_iam_role.isolation_automation
}

moved {
  from = aws_iam_role_policy.isolation_automation
  to   = module.playbook_roles.aws_iam_role_policy.isolation_automation
}

moved {
  from = aws_iam_role.stale_keys_automation
  to   = module.playbook_roles.aws_iam_role.stale_keys_automation
}

moved {
  from = aws_iam_role_policy.stale_keys_automation
  to   = module.playbook_roles.aws_iam_role_policy.stale_keys_automation
}

moved {
  from = aws_iam_role.revoke_sessions_automation
  to   = module.playbook_roles.aws_iam_role.revoke_sessions_automation
}

moved {
  from = aws_iam_role_policy.revoke_sessions_automation
  to   = module.playbook_roles.aws_iam_role_policy.revoke_sessions_automation
}
