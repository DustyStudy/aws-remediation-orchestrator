# Changelog

All notable changes to this repo are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
