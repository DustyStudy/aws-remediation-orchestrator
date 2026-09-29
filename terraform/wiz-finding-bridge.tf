# Optional second intake path: Wiz webhook deliveries are imported into
# Security Hub as ASFF findings, and from there reach the state machine
# through the same EventBridge rule as every other finding. Match them in
# the policy registry with generator_id prefix "wiz/".

module "wiz_finding_bridge" {
  source = "./modules/wiz-finding-bridge"
  count  = var.enable_wiz_finding_bridge ? 1 : 0

  name_prefix             = local.name_prefix
  notification_email      = var.notification_email
  code_signing_config_arn = var.code_signing_config_arn
}
