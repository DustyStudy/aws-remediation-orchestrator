# Proof that aws-remediation-orchestrator works

Three live runs against real AWS accounts, each checked against AWS's own
records (Step Functions history, DynamoDB, SSM Automation, CloudTrail)
rather than only the tool's output. Account IDs are masked.

- [Run 3 (2026-10-07)](#run-3-2026-10-07-the-iam-user-and-instance-playbooks-deny-and-timeout):
  the three playbooks run 2 could not reach (compromised credentials,
  stale access keys, instance isolation), each changing real resources in
  a member account, plus a denied and a timed-out approval.
- [Run 2 (2026-10-04)](#run-2-2026-10-04-org-mode-auto-remediation-and-guardrails):
  org mode across four accounts of a real AWS organization. Auto and
  approved playbooks changed real resources in three accounts, and every
  guardrail fired. **Found two defects in released code**, both fixed.
- [Run 1 (2026-09-22)](#run-1-2026-09-22-single-account-pipeline-and-approval):
  one account. The finding pipeline, the policy fallback and the
  approval gate with a real email click.

## Run 3 (2026-10-07): the IAM-user and instance playbooks, deny and timeout

The same [`examples/org-mode`](../examples/org-mode) deployment as run 2:
the hub in the Security Hub delegated administrator account and the
playbook roles in two member accounts, with the organization's service
control policies in force.
[`live_test_playbooks.py`](../examples/org-mode/live_test_playbooks.py)
created the targets and sent the findings. It covers the three playbooks
and the two approval outcomes that run 2 left to unit tests.

### What was tested

| | |
|---|---|
| **Accounts** | Hub and two member accounts |
| **Resources** | Three IAM users with one active access key each, one of them tagged `break-glass`; a running `t3.nano` in the default security group; an IAM role with no permissions |
| **How the users were created** | This organization's SCPs deny IAM users and access keys in member accounts to everyone but a few exempt roles. A service-managed StackSet from the management account created the users, so no secret access key ever left CloudFormation |
| **Findings** | Imported with `BatchImportFindings` in the account that owns the resource, shaped like GuardDuty's and Security Hub's own, then delivered by Security Hub to the hub |
| **Policy modes** | The three playbooks ran in `auto`, so the run needed nobody to approve them; run 2 covers approval. `approval_timeout_seconds` was 600 |
| **Stale-key threshold** | `stale_key_max_age_days = -1`. An access key cannot be backdated, so the threshold was lowered until a key created minutes earlier counted as stale. The age arithmetic is covered by unit tests |

All evidence is in [`proof/playbooks-run.json`](proof/playbooks-run.json).

### Claims and evidence

| # | Claim | Result | Evidence |
|---|---|---|---|
| 1 | `DisableCompromisedCredentials` deactivates the user's keys and tags the user, in a member account | **Proven** | `compromised-credentials`: `executed`, automation `Success`, started by `remediation-orchestrator-member-execution-role` in the member account. The key went from `Active` to `Inactive` and the user carries `CompromisedCredentials` and `RemediationFindingId` |
| 2 | The user is taken from the finding's access-key details, not from the resource ID | **Proven** | The finding's resource ID was an access key ID, as in a real GuardDuty finding; the user named in `PrincipalName` is the one that changed |
| 3 | `DeactivateStaleAccessKeys` deactivates a stale key | **Proven** | `stale-keys-stale`: `executed`, automation `Success`; the key is `Inactive` |
| 4 | A user carrying the exempt tag is skipped | **Proven** | `stale-keys-exempt`: the automation ran with the same threshold and succeeded, and the key is still `Active` |
| 5 | `IsolateCompromisedInstance` tags, snapshots and isolates a running instance | **Proven** | `compromised-instance`, in the second member account: `executed`, automation `Success`. The instance carries `IsolatedForIR` and `IsolationFindingId`; one completed 8 GB snapshot is tagged with the instance ID; the instance's only security group is now the one tagged `incident-response-isolation`, with 0 ingress and 0 egress rules, where it had been `default` |
| 6 | The instance keeps running unless told to stop | **Proven** | Instance state `running`; the `StopInstanceStep` step never left `Pending` |
| 7 | Deny, in org mode, stops the playbook | **Proven** | `approval-denied`: `denied`, `decided_by: human (approval link)`. The callback answered `Denied. The remediation will not run.` |
| 8 | A request nobody answers is recorded as denied when it times out | **Proven** | `approval-timeout`: `denied`, `decided_by: system (approval timed out)`, ten minutes after the request |
| 9 | Neither denied request changed the role | **Proven** | The target role has no inline policies. `RevokeRoleSessions` would have added one |
| 10 | These playbooks work under SCPs that deny IAM user and key creation | **Proven** | The member playbook roles are not exempt from the organization's SCPs. Deactivating a key and tagging a user are not what the SCPs deny, so the playbooks ran with no exemption |

### What running it for real found

No defect in the playbooks, the roles or the pipeline: every claim held on
the first attempt.

One thing about redeploying surfaced. The first `terraform apply` stopped
at the approval signing secret, because the secret from run 2 was still
inside its seven-day recovery window and Secrets Manager will not reuse
the name. Anyone who destroys a deployment and applies it again within a
week meets this. Delete the old secret with
`aws secretsmanager delete-secret --force-delete-without-recovery`, then
apply again.

### What this run does not prove

- **A key that is stale by age.** The threshold was lowered instead; see
  the table above.
- **A fresh key staying active** next to a stale one on the same user.
  Covered by unit tests.
- **Stopping the instance** (`isolation_stop_instance = true`), and an
  instance with more than one network interface or volume.
- **A deny opened by a person.** The test script opened the Deny link it
  read from an SQS subscription to the notifications topic. Run 1 covers
  a person clicking it.
- **Real GuardDuty and Security Hub findings for these playbooks.** The
  findings were imported, with the types and generator IDs AWS documents.
- **Other regions, scale, GovCloud and cost**, as in run 2.

### Reproduce it

1. Deploy `examples/org-mode` as in run 2, with the `terraform.tfvars.example`
   in that folder as it stands: it holds the three playbook policies in
   `auto` mode and the three test settings.
2. `python live_test_playbooks.py setup --hub <profile> --member-a <profile> --member-b <profile>`.
   Add `--management <profile>` if SCPs deny IAM users in member accounts.
3. Run `send`, then `deny`.
4. Wait `approval_timeout_seconds`, then run `collect`. It writes
   `live-test-playbooks-evidence.json` with account IDs masked.
5. Run `cleanup`, then `terraform destroy`.

## Run 2 (2026-10-04): org mode, auto-remediation and guardrails

Deployed with [`examples/org-mode`](../examples/org-mode): the
orchestrator in the organization's Security Hub delegated administrator
account (the hub) and the playbook roles in two member accounts, 133
resources in one `terraform apply`. The organization's own service control
policies were in force in every member account throughout.
[`live_test.py`](../examples/org-mode/live_test.py) created the test
resources and sent the findings.

### What was tested

| | |
|---|---|
| **Accounts** | Hub (Security Hub delegated administrator), two member accounts, and a fourth account in the organization with no roles in it |
| **Resources** | Real, deliberately non-compliant and attached to nothing: three S3 buckets with Block Public Access off, a security group with four ingress rules, an IAM role with no permissions |
| **Findings** | Imported with `BatchImportFindings` in the account that owns the resource, then delivered by Security Hub to the hub. The control findings (S3.8, EC2.13) are shaped like Security Hub's own, because AWS Config is off in this organization. GuardDuty also raised real findings of its own; see claim 1 |
| **Approval** | A real signed link from the notifications topic, opened by a person |

### Claims and evidence

All evidence is in [`proof/org-mode-run.json`](proof/org-mode-run.json).

| # | Claim | Result | Evidence |
|---|---|---|---|
| 1 | Findings from every account reach the hub | **Proven** | Ledger entries for all four accounts. Besides the imported findings, GuardDuty raised three real `Policy:S3/BucketBlockPublicAccessDisabled` findings about the test buckets in two accounts and a sample finding in a third. All four arrived unprompted and were recorded as `dry_run` |
| 2 | `auto` mode remediates in the hub's own account | **Proven, after a fix** | `s3-hub`: `executed`, automation `Success`; the bucket's four Block Public Access settings went from false to true |
| 3 | `auto` mode remediates in a member account, and the playbook runs there | **Proven, after a fix** | `s3-member`: `executed`. The automation was read back with the member account's own credentials, was started by `remediation-orchestrator-member-execution-role` in that account, and ran the hub's shared document by ARN |
| 4 | `RevokeOpenSshRdpIngress` closes only internet-wide risky ports | **Proven** | `sg-member`, in the second member account. Before: 22, 5432 and 443 from `0.0.0.0/0`, and 22 from `10.0.0.0/8`. After: 443 from `0.0.0.0/0` and 22 from `10.0.0.0/8` |
| 5 | A `do-not-remediate` tag in a member account blocks the playbook | **Proven** | `s3-denylisted`: `blocked`, `resource_tagged_do_not_remediate`, read through the member guardrails role. That bucket's settings are still false |
| 6 | Approve runs the playbook, in a member account | **Proven** | `role-sessions`: `approval_required`, `decided_by: human (approval link)`, `executed`. The role now carries the `AWSRevokeOlderSessions` deny policy with the run's timestamp |
| 7 | A finding from an account with no roles is logged and left alone | **Proven** | `not-onboarded`: `blocked`, `account_not_onboarded`, all three times it was sent |
| 8 | The per-policy rate limit holds | **Proven** | `rate-1` to `rate-7`, limit 2 per hour: the first two `dry_run`, the next five `blocked`, `rate_limit_exceeded` |
| 9 | Past three times the limit, the circuit breaker trips and pauses every account | **Proven, after a fix** | Second pass of `rate-*`: `circuit_breaker_paused` from the second finding on. While paused, the S3 and security group findings in all three accounts were `blocked` with the same reason |
| 10 | `export_evidence` writes one evidence document per account | **Proven** | Four documents from 36 ledger entries, each with its `sha256`, NIST controls and outcome counts |
| 11 | Teardown removes everything in every account | **Proven** | `terraform destroy`: 133 destroyed. Afterwards the hub had no functions, tables, documents, key aliases or evidence bucket, and no account had a `remediation-orchestrator-*` role |

### What running it for real found

`terraform validate`, tflint, Checkov, ruff and pytest all passed before
each of these surfaced.

| # | Found | By | Fixed |
|---|---|---|---|
| 1 | **No playbook could start.** The `execute_remediation` role allowed `ssm:StartAutomationExecution` on `aws_ssm_document.*.arn`, which for an Automation document is `automation-definition/<name>`. SSM authorizes the call against `document/<name>` and against the `automation-execution/*` it is about to create, so every start was denied. This is in v1.1.0 and affected `auto` and approved remediations alike; Run 1 never reached this step | First `auto` finding: `AccessDeniedException` in the Step Functions history, recorded as `failed` in the ledger | The policy names the `document/` and `automation-definition/` ARNs of the six playbooks, and allows the action on `automation-execution/*`. The member execution role got the same treatment |
| 2 | **The circuit breaker could not trip.** Setting the pause parameter overwrites a SecureString, which needs `kms:Encrypt` on the data key. The role had only `kms:Decrypt` and `kms:GenerateDataKey*`, and the handler logged a warning without the cause, so the breaker stayed off without a trace of why. Also in v1.1.0 | Seven findings past a limit of two left the parameter `false`; CloudTrail showed the denied `kms:Encrypt` | `kms:Encrypt` on the data key for the `check_guardrails` role, and the warning now includes the error |
| 3 | A type error in the new org-mode policy that appears only when member accounts are set, which `terraform validate` does not evaluate | First `terraform plan` | Both branches of the conditional now have the same type |
| 4 | The email subscription to the notifications topic went to `Deleted` within a minute of being created, and again after it was confirmed by hand. A further subscribe request produced no confirmation email. The cause was not established; automated link-following by a mail scanner or browser is the usual one | `list-subscriptions-by-topic` | Not a code change. For this run the approval request was read from an SQS subscription to the same topic. For a real deployment, confirm with `aws sns confirm-subscription --authenticate-on-unsubscribe true`, or subscribe a chat or ticketing integration |

The approval link also had a doubled slash before `decision`. It worked,
and is now built with a single slash.

### What this run does not prove

- **Real Security Hub control findings.** AWS Config is off in this
  organization, so no control produced a finding. The S3.8 and EC2.13
  findings were imported with the generator IDs Security Hub documents;
  the match values in `terraform.tfvars.example` are still unverified
  against a control's real output.
- **Three playbooks.** *Covered by Run 3.* `DisableCompromisedCredentials` and
  `DeactivateStaleAccessKeys` need an IAM user, which this organization's
  SCPs do not allow in member accounts. `IsolateCompromisedInstance` needs
  an instance. All three are covered by unit tests only.
- **Deny and timeout in org mode.** *Covered by Run 3.* Run 1 covers deny in one account.
- **Approval by email.** Run 1 covers it; see finding 4 above.
- **Other regions.** One hub in `us-east-1`. This organization aggregates
  findings from two more regions into it, and a playbook for one of those
  would run in the wrong region; see
  [ORG_MODE.md](ORG_MODE.md#limits).
- **Scale.** Two member accounts, a few dozen findings.
- **GovCloud.** Commercial partition only.
- **Cost.** Not measured; the deployment was up for about an hour.

### Reproduce it

Needs an AWS organization with Security Hub and GuardDuty enabled, a
delegated administrator account, and CLI profiles for it and two member
accounts.

1. `cd examples/org-mode && cp terraform.tfvars.example terraform.tfvars`,
   then set the profiles, account IDs and email address.
2. `terraform init && terraform apply`.
3. `python live_test.py setup --hub <profile> --member-a <profile> --member-b <profile>`
   (add `--outside <profile>` for an account with no roles).
4. Run the `auto` stage, then `approval` and open the Approve link, then
   `breaker`. Findings take one to two minutes to arrive.
5. Reset the circuit breaker, then run `collect`. It writes
   `live-test-evidence.json` with account IDs masked.
6. Run `cleanup`, then `terraform destroy`. Stop any execution still
   waiting for approval first: the state machine is not deleted until its
   executions end.

## Run 1 (2026-09-22): single account, pipeline and approval

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

- **The `auto` mode (`s3-public-access`).** *Covered by Run 2.* Its match value (`Software and Configuration Checks/S3`) comes from Security Hub's own control checks, not GuardDuty, and there's no on-demand equivalent of `create-sample-findings` for those - forcing one needs either a real non-compliant resource and a wait for Security Hub's periodic re-scan, or `BatchImportFindings` against a synthetic ASFF document. Neither was done here. The `execute_remediation` Lambda's actual invocation of an SSM Automation document is thus unexercised in this run.
- **`approve`, not just `deny`.** *Covered by Run 2.* The deny path resolves the same task token and runs the same ledger-recording code as approve; it does not exercise `execute_remediation` actually starting the `DisableCompromisedCredentials` SSM document.
- **Guardrails under load.** *Covered by Run 2.* `max_actions_per_hour` and the circuit breaker (`/remediation-orchestrator/paused`) were never exercised - only one finding per policy ran, well under any rate limit.
- **`export_evidence`.** *Covered by Run 2.* The scheduled evidence exporter (`rate(1 day)`) was not manually invoked or verified against the ledger entries this run produced.
- **Multi-account / GovCloud.** Tested in one commercial-partition account only. *Run 2 covers multi-account.*
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

`docs/proof/pipeline-executions.json` and `policy-registry-item.json` hold the machine-readable evidence from this run.
