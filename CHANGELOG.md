# Changelog

All notable changes to this repo are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `RevokeRoleSessions` playbook: denies every session of the IAM role in a
  GuardDuty credential finding that was issued before now, using the same
  `AWSRevokeOlderSessions` policy as the IAM console. It refuses to act on
  a role in another account, on Identity Center roles, on service-linked
  roles and on the orchestrator's own roles. `DisableCompromisedCredentials`
  only covers IAM user keys, so stolen role credentials had no playbook.
- Normalized findings carry `principal_role_name`, read from the ASFF
  `AwsIamAccessKey` resource, for playbooks that act on a role.
- Three playbooks, ported from aws-cloud-security-toolbox so the
  orchestrator no longer depends on another repo's documents:
  - `RevokeOpenSshRdpIngress`: revokes internet-wide 22/3389 ingress.
  - `IsolateCompromisedInstance`: snapshots volumes, then moves every
    network interface to a per-VPC isolation group it creates on first use.
  - `DeactivateStaleAccessKeys`: deactivates only a user's stale keys
    (defaults match Security Hub IAM.3 and IAM.22).
- `modules/wiz-finding-bridge`, off by default: imports Wiz webhook
  deliveries into Security Hub as ASFF findings with a `wiz/` generator id.
- `playbook_document_names` output, and seed examples for the new
  playbooks in `terraform.tfvars.example`.
- Unit tests for every playbook script and the Wiz bridge.

### Fixed
- The `do-not-remediate` tag check called the tagging API with any
  resource id. A third-party finding whose resource id isn't an ARN made
  that call fail. Non-ARN ids now skip the check.

## [1.0.0] - 2026-09-29

First tagged release.

### Added
- Security Hub finding pipeline: EventBridge to Step Functions (normalize,
  policy lookup, guardrails, route by mode) with Lambda and SSM Automation.
- Policy registry in DynamoDB with `auto`, `approval_required`, `dry_run`
  and `ignore` modes, seeded from Terraform.
- Guardrails: per-policy hourly rate limit and a circuit breaker.
- Human approval gate: HMAC-signed approve/deny links sent through SNS.
- Audit ledger with a scheduled compliance-evidence export to a
  KMS-encrypted S3 bucket.
- Dispatch to externally owned SSM documents through
  `external_ssm_document_arns`.
- `enable_lambda_reserved_concurrency` for accounts with a low Lambda
  concurrency quota.
- CI: ruff, pytest, tflint, Checkov, Trivy and Gitleaks.
- `docs/PROOF.md`: end-to-end run against a real AWS account.

### Fixed
Found during the real-account run in `docs/PROOF.md`:
- Approval callback failed on every click because `consumed` is a DynamoDB
  reserved word. It now uses `ExpressionAttributeNames`.
- A null `severity_threshold` was stored as the string `"true"` instead of
  a DynamoDB NULL.
- The KMS key policy did not allow the Step Functions and API Gateway log
  groups, so their creation failed.

[Unreleased]: https://github.com/DustyStudy/aws-remediation-orchestrator/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/DustyStudy/aws-remediation-orchestrator/releases/tag/v1.0.0
