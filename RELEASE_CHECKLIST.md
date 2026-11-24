# Release checklist: next release (proposed 2.0.0)

Baseline: `main` at `72d6d3e`. Release candidate: branch
`claude/project-thread-aloekb`. Updated 2026-11-24.

There is no roadmap, milestone or open issue for this release. Its scope is
the `[Unreleased]` section of `CHANGELOG.md` plus the documented behavior in
`README.md` and `docs/`. Supported environments: Terraform >= 1.5 (>= 1.7 for
`terraform test`), Python 3.12 Lambda runtime, AWS commercial and GovCloud
partitions, single-account and org mode.

**Status: BLOCKED** on live verification (L1) of the changes made after the
last live run. Everything that can be checked without an AWS account passes.

## Versioning

`[Unreleased]` contains a **breaking** approval change (GET links are
read-only; decisions need an IAM-signed POST; the callback result format
changed). Under Semantic Versioning, which `CHANGELOG.md` says this repo
follows, that is a major bump: **2.0.0**, not 1.3.0. Tagging and publishing
the release need the owner's approval.

## Static and unit checks

Run locally from a fresh clone and a fresh virtualenv
(`pip install --require-hashes -r requirements-dev.txt`, Python 3.13 locally;
CI uses 3.12).

| # | Criterion | Status | Evidence |
|---|---|---|---|
| C1 | `python -m compileall -q terraform tests scripts` succeeds | PASS | Fresh-clone run on the RC |
| C2 | `ruff check terraform tests scripts` is clean (includes the `S` security rules) | PASS | "All checks passed!" |
| C3 | `pytest tests -q` passes | PASS | 197 passed on the RC (184 on baseline) |
| C4 | `terraform fmt -check -recursive terraform` | PASS | No diff |
| C5 | `terraform validate` (root module and `examples/org-mode`) | PASS | Terraform 1.13.3, hashicorp/aws 6.74.0, archive 2.8.1, random 3.9.1 |
| C6 | `terraform test` passes (mocked providers) | PASS | 2 runs passed: `workflow_contract`, `approval_timeout_cannot_outlive_the_link`. `terraform.tfvars.example` also applies under the mocks with its `product` seeds |
| C7 | `tflint` is clean | PASS | tflint 0.59.1, no issues |
| C8 | Checkov: no failed checks | PASS | 386 passed, 0 failed, 29 skipped (each skip has an inline reason) |
| C9 | GitHub Actions workflows pass zizmor; every action is SHA-pinned; workflow permissions are `contents: read` by default | PASS | `zizmor --offline`: no findings (1 suppressed) |
| C10 | No known vulnerabilities in pinned Python dependencies | PASS | `pip-audit -r requirements-dev.txt`: none found. Lambdas use only the runtime's boto3 |
| C11 | CI on the PR (pytest/ruff, Terraform, Checkov, CodeQL, Gitleaks, Trivy, zizmor) is green | PENDING | Runs on the PR; `main` at `72d6d3e` is green |

## Critical workflows

Unit tests and `terraform test` mock AWS. They prove the logic and the state
machine wiring, not AWS authorization or service behavior.

| # | Workflow | Mocked evidence | Live evidence |
|---|---|---|---|
| W1 | Batch normalization; malformed findings recorded as rejected | `test_normalize_batch.py`, `workflow_contract` | Run 4 (2026-10-10) |
| W2 | Policy matching (type, generator, CVE, resource type, product, severity floor) | `test_policy.py`, `test_asff.py` | Runs 1-4 for type and generator. CVE routing and `product` not live |
| W3 | Guardrails: circuit breaker, rate limit, auto-trip, tag denylist, onboarding | `test_guardrails.py`, `test_check_guardrails.py` | Run 2 |
| W4 | Approval: read-only GET, IAM POST, immutable decision, retry, timeout as deny | `test_approval_callback.py`, `test_decide.py`, `workflow_contract` | Run 4 |
| W5 | **Approved actions recheck the breaker and tag** (new, S1) | 4 tests in `test_check_guardrails.py`; `workflow_contract` asserts the path and that only two states reach remediation | **Not live** |
| W6 | Six playbooks remediate real resources, including org mode | `test_playbook_*.py` | Runs 2-3. Service-specific credential deactivation (added 2026-10-19) is not live |
| W7 | Ledger, notifications, evidence export | `test_ledger.py`, `test_record_ledger.py` | Runs 2 and 4 |
| W8 | Independent workflow alarms | `workflow_contract` (3 alarms) | Not live (ARCHITECTURE.md says so) |

The project has four live runs in real AWS accounts (README "What the live
runs check", `docs/PROOF.md`). The latest, run 4 on 2026-10-10, tested
revision `f2ac7c0`, which already included the LiteLLM/Ollama port defaults.
Run 4 covers W1, W4 and W7, and runs 2 and 3 cover W3 and W6, for the code they tested.
These changes landed after `f2ac7c0` and have never run live:

| Change | Commit | Needed live check |
|---|---|---|
| Post-approval guardrail recheck | this PR | Approve with the breaker set during the wait: expect `blocked` with the approver recorded. Approve with it clear: expect `executed` |
| `product` policy filter | this PR | A real GuardDuty sample finding matches a `product = "aws/guardduty"` rule. A `BatchImportFindings` copy of it falls to `default` |
| Service-specific credential deactivation (Bedrock API keys) | `c0cb776` | `DisableCompromisedCredentials` on a user with a Bedrock API key: the key becomes `Inactive` |
| Inspector CVE routing | `3698c6b` | Optional: needs a real Inspector finding for a chosen CVE |
| KMS key deletion window, port 3000 docs | `6c45d4c`, `ff4df88` | None: plan-time setting and docs |

| # | Live criterion | Status | Blocker / next action |
|---|---|---|---|
| L1 | One sandbox deployment of the RC passes the first three checks above | **OPEN** | Needs an owner-approved sandbox account and spend. Follow `docs/PROOF.md` §4 and `examples/org-mode/live_test_approval.py`. Record the result as run 5 in `docs/PROOF.md` and the README |

## Security

Trust boundaries: Security Hub findings (anyone with
`securityhub:BatchImportFindings`, the Wiz webhook, member accounts in org
mode) → normalizer and policy registry → guardrails → human approver (signed
link + IAM POST) → playbook roles that change IAM, EC2 and S3 resources.
Sensitive data: Step Functions task tokens, the HMAC signing secret, the Wiz
webhook token, approver identities, the audit ledger.

| # | Finding | Severity | Status | Evidence |
|---|---|---|---|---|
| S1 | An approval could bypass the circuit breaker and `do-not-remediate` tag. Guardrails ran only before the request; a breaker set or tag added during the wait (up to 24 h) did not stop an approved playbook. SECURITY.md lists breaker bypass as in scope | High | **FIXED** | `RecheckGuardrails`/`RecheckChoice` in `stepfunctions.tf`; recheck mode in `check_guardrails`; regression tests fail on the old code |
| S2 | Approvers could not see a finding's source. A forged GuardDuty-shaped finding looked identical to a real one in the email | Medium | **MITIGATED** | Email names `ProductArn` and `GeneratorId`; `test_request_approval.py`; OPERATIONS.md step 2 |
| S3 | `approval_timeout_seconds` > 86400 outlived the link's 24 h lifetime, so every approval would time out | Low | **FIXED** | Variable validation; `approval_timeout_cannot_outlive_the_link` test |
| S4 | Any same-account principal with `execute-api:Invoke` on the API (for example an admin with `*`) can submit a decision if they also have the emailed link | Info | Documented design | ARCHITECTURE.md "Deliberate limits"; OPERATIONS.md tells operators to grant narrowly |
| S5 | Policy matching was not bound to the finding's source. Anyone with `BatchImportFindings` in the deployment's account (or a member account, in org mode, for its own account) could trigger `auto` playbooks and approval requests | Medium | **FIXED** (owner chose the filter, 2026-11-24) | Optional `product` field on policy items (`aws/guardduty`, `aws/inspector`, `aws/securityhub`), matched against the finding's `ProductArn`. Every acting rule in `terraform.tfvars.example` sets it. `examples/org-mode` leaves it out because its live tests import findings. Tests: `test_policy.py`, `test_asff.py`. Relies on Security Hub assigning `<account>/default` to self-imported findings, which needs live confirmation (L1) |
| S6 | IAM least privilege | - | PASS | Reviewed all roles. Wildcards are limited to actions without resource-level support (`states:SendTaskSuccess`, `tag:GetResources`, EC2 Describe, X-Ray, log delivery) or targets known only at run time, each commented. Member roles trust one hub function |
| S7 | Secrets | - | PASS | Signing and Wiz secrets are generated by Terraform, held in Secrets Manager with a CMK and never in environment variables; HMAC and token comparisons are constant-time; no secrets in the repo (Gitleaks on `main`). Terraform state holds both generated values, so the state backend must be access-controlled and encrypted |
| S8 | Input validation and logging | - | PASS | Normalizer rejects malformed ASFF without storing the payload; the Wiz bridge rejects bad tokens with 401 and strips SNS subject characters; `decide.py` accepts only HTTPS API Gateway hosts and never follows redirects |
| S9 | CI and release permissions | - | PASS | Workflows default to `contents: read`; only CodeQL/scan jobs get `security-events: write`; `persist-credentials: false`; Harden Runner on every job |
| S10 | AI features | N/A | - | The project has no model calls. Its AI-related playbooks act on findings about AI services only |

## Decisions

- **Recheck in the state machine, not in `execute_remediation`.** Reusing
  `check_guardrails` keeps its existing IAM and member-account roles, and
  needs no new permissions. The recheck skips the rate limit, since the
  finding was counted before the approval. It applies to the approval path
  only; the `auto` path goes straight from the guardrail check to the playbook.
- **A recheck error fails closed** to `RecordPipelineFailed`, like the other
  pipeline errors.
- **`product`, not a full `ProductArn`.** The value is the part after
  `product/`, so one rule works in every region and partition. Existing
  registry items without it keep matching as before.
- **Next version is 2.0.0** because of the breaking approval API change.
