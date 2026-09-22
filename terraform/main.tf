data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  name_prefix = var.name_prefix
  partition   = data.aws_partition.current.partition
  account_id  = data.aws_caller_identity.current.account_id
  region      = data.aws_region.current.region
  arn_prefix  = "arn:${local.partition}"
  common_tags = merge(var.tags, {
    Application = "aws-remediation-orchestrator"
  })
}
