# Proof that aws-remediation-orchestrator works

Run for real on **2026-09-22** against a real AWS account with Security Hub and
GuardDuty enabled: deployed via `terraform apply`, fed real (GuardDuty-sample)
findings through the real EventBridge -> Step Functions -> Lambda pipeline,
and one finding was carried all the way through a real human clicking a real
approve/deny link in a real email. Verified against AWS's own records
(Step Functions execution history, DynamoDB scans, CloudWatch Logs) rather
than only the tool's own output. The account ID is masked below and in the
evidence files.

The point isn't that it worked first time - it didn't, four times over (see
section 2). The point is that each claim below has evidence a reader can
check and a way to reproduce it.

## What was tested

| | |
|---|---|
| **Account** | One AWS account, real Security Hub + GuardDuty enabled for the run, disabled again afterward |
| **Deploy** | `terraform apply` from `terraform/`, `policy_registry_seed` = the three items in `terraform.tfvars.example` verbatim, `enable_lambda_reserved_concurrency = false` (this account's Lambda concurrency limit is 10 - see bug #2) |
| **Findings** | `aws guardduty create-sample-findings` - real synthetic findings through the real GuardDuty -> Security Hub integration, not fabricated EventBridge input |
| **Approval** | A real SNS email subscription (confirmed by the person running this), a real click on the emailed deny link |

## 1. Claims and evidence

| # | Claim | Result | Evidence |
|---|---|---|---|
| 1 | A Security Hub finding flows EventBridge -> Step Functions -> normalize -> lookup_policy -> check_guardrails -> record_ledger | **Proven** | [`pipeline-executions.json`](proof/pipeline-executions.json), executions 1-2: two real GuardDuty sample findings, two `SUCCEEDED` executions, two ledger entries with `mode: dry_run` |
| 2 | The `default` policy is a true fallback - an unmatched finding is logged, not silently dropped | **Proven** | Same file: both findings' real ASFF `Types` didn't match any specific rule and fell through to `default`/`dry_run` |
| 3 | The registry's own documented caveat ("match values aren't guaranteed ASFF strings without checking a live finding") is true, not just a hedge | **Proven** | Same file: `terraform.tfvars.example`'s `guardduty-compromised-credentials` rule (`Unusual Behaviors/User`) never matched either real GuardDuty finding's actual `Types` |
| 4 | The break-glass DynamoDB edit path documented in `POLICY_REGISTRY.md` works, and a plain `terraform apply` reverts it | **Proven** | A `match_value` edited directly in the table took effect on the next finding; the next `terraform apply` (deploying the bug #4 fix) silently reverted it back to the tfvars value, exactly as an unmanaged drift would |
| 5 | `approval_required` pauses the state machine on a real task token and sends a real signed link | **Proven** | [`pipeline-executions.json`](proof/pipeline-executions.json), execution 3: state machine `RUNNING`, `pending-approvals` item with `consumed: false` and a real task token, real SNS email received |
| 6 | Clicking deny resolves the task token, denies the execution, and records who decided | **Proven, after a fix** | Same file: `SUCCEEDED`, `outcome: denied`, `decided_by: "human (approval link)"`, `pending-approvals` item now `consumed: true` |
| 7 | The seeded policy registry's `severity_threshold: null` case stores correctly as a native DynamoDB NULL | **Proven, after a fix** | [`policy-registry-item.json`](proof/policy-registry-item.json) |
| 8 | Teardown removes everything, including the KMS-encrypted evidence bucket | **Proven** | `terraform destroy`: 87 destroyed, 0 remaining; `aws lambda list-functions` / `list-tables` / `s3api head-bucket` all empty/404 afterward |

## 2. What running it for real found

None of these were caught by `terraform validate`, `tflint`, Checkov, ruff,
or pytest - all passed before every one of them surfaced. Three broke the
deploy outright; the fourth broke the module's core safety feature
(a human being able to stop an automated action) silently, returning a
generic-looking failure with no indication the click had no effect.

| # | Found | By | Fixed |
|---|---|---|---|
| 1 | `dynamodb.tf`'s `severity_threshold = cond ? {NULL=true} : {S=str}` unifies the two branches' object types; HCL coerces the bool to the string `"true"`, and DynamoDB then rejects it: `unexpected raw attribute type (string) for data type descriptor: NULL` | First `terraform plan` | Routed both branches through `jsonencode`/`jsondecode` so the ternary only ever unifies plain strings; see `dynamodb.tf` |
| 2 | All 8 Lambdas' hardcoded `reserved_concurrent_executions` (summing to 131) assume an account with the standard 1,000-execution concurrency quota. This account's real limit is 10 - a fresh account default, not unusual - so `PutFunctionConcurrency` failed on every function: *"decreases account's UnreservedConcurrentExecution below its minimum value of [10]"* | First `terraform apply` | New `var.enable_lambda_reserved_concurrency` (default `true`, preserves existing behavior); set `false` to deploy unreserved. See `variables.tf` and every `lambda-*.tf` |
| 3 | The shared KMS key's policy only grants CloudWatch Logs access for `/aws/lambda/<prefix>-*` log groups. The Step Functions state machine's log group (`/aws/vendedlogs/states/<prefix>`) and the API Gateway access-log group (`/aws/apigateway/<prefix>-*`) reuse the *same key* but don't match that pattern, so `CreateLogGroup` failed for both: *"The specified KMS key does not exist or is not allowed to be used"* | Second and third `terraform apply` (one failure each, sequentially) | Added both log-group ARN patterns to the key's `ArnLike` condition. See `lambda-common.tf` |
| 4 | **The approval callback never worked.** `consumed` is a DynamoDB reserved keyword; referencing it bare in `UpdateExpression`/`ConditionExpression` fails at parse time with `ValidationException`, not the `ConditionalCheckFailedException` the code's `except` clause was written to catch - so every approve/deny click, ever, silently failed while the API still returned nothing indicating success or failure to the Lambda's own caller (API Gateway logged the 500; the emailed link gave no visible error). The rest of the codebase (`guardrails.py`) already used `ExpressionAttributeNames` for its own reserved words (`count`, `ttl`) - this was an isolated miss in one file | Clicking a real deny link end to end, then reading the Lambda's CloudWatch Logs | Added `ExpressionAttributeNames` and referenced `#consumed` in both expressions. See `terraform/lambda/approval_callback/handler.py` |

## 3. What this does not prove

- **The `auto` mode (`s3-public-access`).** Its match value (`Software and Configuration Checks/S3`) comes from Security Hub's own control checks, not GuardDuty, and there's no on-demand equivalent of `create-sample-findings` for those - forcing one needs either a real non-compliant resource and a wait for Security Hub's periodic re-scan, or `BatchImportFindings` against a synthetic ASFF document. Neither was done here. The `execute_remediation` Lambda's actual invocation of an SSM Automation document is thus unexercised in this run.
- **`approve`, not just `deny`.** The deny path resolves the same task token and runs the same ledger-recording code as approve; it does not exercise `execute_remediation` actually starting the `DisableCompromisedCredentials` SSM document.
- **Guardrails under load.** `max_actions_per_hour` and the circuit breaker (`/remediation-orchestrator/paused`) were never exercised - only one finding per policy ran, well under any rate limit.
- **`export_evidence`.** The scheduled evidence exporter (`rate(1 day)`) was not manually invoked or verified against the ledger entries this run produced.
- **Multi-account / GovCloud.** Tested in one commercial-partition account only.
- **The approval link's known limitation.** `approval_callback/handler.py`'s own docstring notes the HMAC signature proves the link wasn't tampered with, not who clicked it - anyone with the email can decide. Not attacked or re-verified here.
- **Cost.** Real Lambda/Step Functions/DynamoDB/KMS/Secrets Manager charges accrued for roughly the hour this was live; not measured.

## 4. Reproduce it

Prerequisites: an AWS account with Security Hub and GuardDuty enabled (or
enable them as part of this - `aws guardduty create-detector --enable` /
`aws securityhub enable-security-hub`); an email address you can confirm an
SNS subscription from.

1. `cd terraform && cp terraform.tfvars.example terraform.tfvars`, set `notification_email`. If your account's Lambda concurrency limit is under ~150 (`aws lambda get-account-settings`), also add `enable_lambda_reserved_concurrency = false`.
2. `terraform init && terraform apply`.
3. Confirm the SNS subscription email.
4. `aws guardduty create-sample-findings --detector-id <id> --finding-types "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS" "Policy:IAMUser/RootCredentialUsage"` - wait ~1-2 minutes for Security Hub to ingest them from GuardDuty.
5. `aws stepfunctions list-executions --state-machine-arn <arn>` - expect two `SUCCEEDED` executions; `aws dynamodb scan --table-name <prefix>-remediation-ledger` to see both landed on `default`/`dry_run`.
6. To exercise `approval_required` with a value that will actually match: read the real finding's `Types` from the ledger or `aws securityhub get-findings`, then `aws dynamodb update-item` the `guardduty-compromised-credentials` policy's `match_value` to that prefix (see `POLICY_REGISTRY.md`'s break-glass note), and generate a fresh sample finding of the same type.
7. Confirm the execution is `RUNNING`, find the approval email, click deny (or approve, if you're prepared for `DisableCompromisedCredentials` to actually run against the sample finding's principal).
8. Re-check the execution (`SUCCEEDED`) and the ledger (`outcome: denied` or the remediation's own outcome).
9. `terraform destroy` (with `evidence_bucket_force_destroy = true` in tfvars, or empty the evidence bucket first), then disable GuardDuty/Security Hub if you enabled them only for this.

`docs/proof/` holds the machine-readable evidence from the run above.
