# Changelog

All notable changes to this repo are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- A timed-out execution no longer leaves its findings out of the audit
  ledger. Step Functions stops a timed-out execution without running a
  catch state, so a finding still waiting (usually for approval) had no
  ledger item; live run 8 showed this. A new `record_timeout` function,
  invoked by EventBridge when an execution times out, writes a `timed_out`
  item for each finding of the execution that has no item from the
  execution's lifetime. The write is conditional, so a redelivered event
  writes nothing twice, and a failed recording goes to the notifications
  topic. The evidence export counts `timed_out` items and marks the period
  `fail`, like `failed` ones.

### Documentation
- Live run 8 evidence: the 2.1.0 execution time limit stops an execution
  waiting for approval, and the `ExecutionsTimedOut` alarm notifies
  (`docs/PROOF.md`, `docs/proof/run-8.json`).

## [2.1.0] - 2026-11-24

### Added
- `execution_timeout_seconds`: an overall time limit for each workflow
  execution (see below).

### Fixed
- The `ExecutionsTimedOut` alarm can fire. The state machine had no overall
  time limit, so no execution could ever time out. Executions now stop after
  `execution_timeout_seconds` (new variable; default
  `approval_timeout_seconds` plus two hours), which covers one approval wait
  and every step's throttling retries. A stuck execution now surfaces as an
  alarm instead of running until Step Functions' one-year limit.

## [2.0.1] - 2026-11-24

### Fixed
- A burst of findings no longer drops most of them when the account's Lambda
  concurrency quota is low. In live run 6, about 3,000 Amazon Inspector
  findings on one instance arrived within minutes; with a quota of 10, about
  1,700 executions failed after three quick throttling retries. Every Lambda
  task, including the approval request, now retries
  `Lambda.TooManyRequestsException` up to 12 times with exponential backoff
  capped at 60 seconds and full jitter. A throttled invocation never ran, so
  the retry cannot repeat an action.
- Approval messages state the configured `approval_timeout_seconds` instead
  of always saying "24 hours".

### Maintenance
- Live run 6 on 2.0.0: Amazon Inspector CVE routing isolated a real
  instance, and the aborted and failed workflow alarms were delivered through
  the encrypted topic (`docs/proof/run-6.json`).

## [2.0.0] - 2026-11-24

### Fixed
- Normalize every finding in a batch and retain auditable rejected records.
- Record policy, guardrail and approval-request failures; retry ledger writes
  with a stable timestamp and alarm independently on workflow failures.
- Reserve an immutable approval decision before delivery; retry the same
  decision after transient callback errors without reopening opposing choices.

### Security
- An approved remediation now re-checks the circuit breaker and the
  `do-not-remediate` tag before it runs. Before, a breaker set or a tag
  added while the approval waited (up to `approval_timeout_seconds`) did
  not stop the action once someone approved it. The recheck does not count
  against the rate limit again. A blocked approval is recorded as `blocked`
  with the approver as `decided_by`; a recheck error is recorded as `failed`.
- `approval_timeout_seconds` is validated to 60-86400 seconds. A longer
  wait outlived the 24-hour approval link and could only end in a timeout.
- Policy items take an optional `product` (`aws/guardduty`,
  `aws/inspector`, `aws/securityhub`) that must match the product in the
  finding's `ProductArn`. A finding imported with `BatchImportFindings` gets
  `<account>/default`, so it can no longer match a rule meant for GuardDuty.
  `terraform.tfvars.example` sets it on every acting rule. Existing items
  without it match as before.
- Approval emails name the finding's `ProductArn` and `GeneratorId`, so an
  approver can tell a finding imported with `BatchImportFindings` from one
  GuardDuty or Inspector raised.
- Document adding port 3000 to `open_ingress_revoke_ports` where Flowise
  runs, after attackers exploited internet-facing Flowise servers
  (CVE-2025-59528, CVE-2026-41264; The Hacker News, 2026). The default
  stays the same because Grafana, Gitea and Gotenberg also use port 3000.
- Route Amazon Inspector findings by CVE: the policy registry gains a
  `vulnerability_id` match field (exact match on the finding's
  `Vulnerabilities[].Id`) and an optional `resource_type` filter.
  `terraform.tfvars.example` seeds approval-required
  `IsolateCompromisedInstance` rules for EC2 instances with php2shell,
  unauthenticated remote code execution in PHP
  ([CVE-2026-109618 and CVE-2026-109619](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)).
  NIST SP 800-53 Rev5: SI-2, IR-4, SC-7.
- `DisableCompromisedCredentials` also deactivates the user's active
  service-specific credentials (Bedrock API keys, CodeCommit Git
  credentials, Keyspaces passwords), which LLMjacking actors add as a
  second way in
  ([FortiGuard Labs, 2026-09-03](https://www.fortinet.com/blog/threat-research/someone-else-is-using-your-ai)).
  The credentials automation role gains
  `iam:ListServiceSpecificCredentials` and
  `iam:UpdateServiceSpecificCredential` on `user/*`. NIST SP 800-53 Rev5:
  IR-4, AC-2(3), IA-5.
- **Breaking approval change:** GET links are read-only; submissions require
  IAM-authenticated POST. Record the IAM actor on both approval and denial.
  Drain existing executions before upgrading; see `docs/OPERATIONS.md`.

### Maintenance
- Share eight identical Lambda trust policies without moving resources.
- Add Python regressions and mocked Terraform workflow tests.
- Live run 5: the guardrail recheck after approval, the `product` filter
  and Bedrock API key deactivation, on the release candidate
  (`docs/proof/run-5.json`).
- Live run of the approval flow, delivery recovery and a batch
  (`docs/CASE-STUDY.md`, run 4 in `docs/PROOF.md`).
- `live_test_playbooks.py deny` submits an IAM-signed POST.


### Changed
- `open_ingress_revoke_ports` now includes 4000 (LiteLLM proxy) and 11434
  (Ollama) by default, so `RevokeOpenSshRdpIngress` closes self-hosted AI
  servers opened to `0.0.0.0/0` or `::/0`. Remove them from the variable
  to keep the old behavior.
- `terraform.tfvars.example` routes Security Hub control EC2.18
  (unrestricted ingress on unauthorized ports) to the same playbook.
  EC2.19 does not report these two ports.

## [1.2.0] - 2026-10-06

### Added
- Third live run (`examples/org-mode/live_test_playbooks.py`):
  `DisableCompromisedCredentials`, `DeactivateStaleAccessKeys` and
  `IsolateCompromisedInstance` run in member accounts against real IAM
  users and a running instance, plus a denied and a timed-out approval in
  org mode. Every claim held; no code change was needed
  (`docs/PROOF.md`). The org-mode example now passes
  `approval_timeout_seconds`, `stale_key_max_age_days` and
  `stale_key_exempt_tag_key` through to the module.
- Org mode. Set `org_member_account_ids` on a deployment in the Security
  Hub delegated administrator account and a playbook for a member
  account's finding runs in that account: `execute_remediation` assumes a
  role there and starts the hub's shared document as the member's own
  playbook role. The `do-not-remediate` tag is read in the member account
  too. A finding from an account that isn't listed is recorded as
  `blocked` with the reason `account_not_onboarded`. See
  `docs/ORG_MODE.md` and `examples/org-mode`.
- `modules/playbook-roles`: the six playbook roles, plus the two roles the
  hub assumes when it is applied in a member account.
- `member_account_config` output with the inputs that module needs.

### Fixed
- No playbook could start: the `execute_remediation` role allowed
  `ssm:StartAutomationExecution` on `automation-definition/<name>` ARNs,
  but SSM authorizes the call against `document/<name>` and
  `automation-execution/*`. Both `auto` and approved remediations were
  denied. Found by the org-mode live run (`docs/PROOF.md`).
- The circuit breaker could not trip: overwriting the SecureString pause
  parameter needs `kms:Encrypt` on the data key, which the
  `check_guardrails` role lacked. The warning it logged now includes the
  error.
- The approval link no longer has a doubled slash before `decision`.

### Changed
- The playbook roles moved from the root module into
  `modules/playbook-roles`. `moved` blocks carry existing state across, so
  an upgrade plans no changes to them.
- The notifications topic and the evidence bucket are now encrypted with
  the module's data CMK instead of the AWS-managed `aws/sns` and `aws/s3`
  keys. The SSM automation roles that publish to the topic get
  `kms:GenerateDataKey*`/`kms:Decrypt` on that key. Objects already in the
  evidence bucket keep their old key until rewritten.
- The data key now sets `deletion_window_in_days = 30` explicitly.
- Trivy inline ignores for the access-log bucket (SSE-S3 is required for
  log delivery) and the rate-limit table (no PITR), matching the existing
  checkov skips.

## [1.1.0] - 2026-09-30

### Changed
- `RevokeOpenSshRdpIngress` now also closes internet-wide database and
  cache ports. A new `RiskyPorts` document parameter takes its default
  from the `open_ingress_revoke_ports` variable: 22, 3389, 1433, 1521,
  3306, 5432, 6379, 9200 and 27017. Set the variable to `[22, 3389]` to
  keep the old behavior. The document name is unchanged, so existing
  policy items keep working.
- `terraform.tfvars.example` routes Security Hub control EC2.19
  (high-risk ports) to the same playbook.
- CI: every workflow is audited by zizmor, every Linux job starts with
  harden-runner in audit mode, and Dependabot waits 7 days before
  proposing an update.

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
- `DisableCompromisedCredentials` took the user name from the finding's
  first resource ID. In Security Hub's copy of a GuardDuty finding that's
  the access key ID or an EC2 instance, so the playbook could never find
  the user. It now gets the user from the `AwsIamAccessKey` resource
  (`principal_user_name`), refuses findings about a role, and refuses a
  finding from another account.
- The `guardduty-compromised-credentials` seed matched
  `Unusual Behaviors/User`, which no GuardDuty finding uses. It now
  matches `TTPs/UnauthorizedAccess:IAMUser-MaliciousIPCaller`.
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

[Unreleased]: https://github.com/DustyStudy/aws-remediation-orchestrator/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/DustyStudy/aws-remediation-orchestrator/compare/v2.0.1...v2.1.0
[2.0.1]: https://github.com/DustyStudy/aws-remediation-orchestrator/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/DustyStudy/aws-remediation-orchestrator/compare/v1.2.0...v2.0.0
[1.2.0]: https://github.com/DustyStudy/aws-remediation-orchestrator/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/DustyStudy/aws-remediation-orchestrator/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/DustyStudy/aws-remediation-orchestrator/releases/tag/v1.0.0
