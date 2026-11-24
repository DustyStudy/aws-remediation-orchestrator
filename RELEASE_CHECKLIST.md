# Release checklist: 2.0.0

Baseline: `main` at `72d6d3e`. Release candidate: branch
`claude/project-thread-aloekb`. Updated 2026-11-24.

There is no roadmap, milestone or open issue for this release. Its scope is
the `[Unreleased]` section of `CHANGELOG.md` plus the documented behavior in
`README.md` and `docs/`. Supported environments: Terraform >= 1.5 (>= 1.7 for
`terraform test`), Python 3.12 Lambda runtime, AWS commercial and GovCloud
partitions, single-account and org mode.

**Status: READY**, pending the owner's approval to merge, tag 2.0.0 and
publish. Every static, unit and mocked check passes, CI is green on the RC,
and live run 5 (2026-11-24) passed on the RC revision `68cb528`. Two live
gaps carry over from earlier releases and are documented, not blocking:
Inspector CVE routing (W2) and alarm delivery (W8).

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
| C11 | CI on the PR (pytest/ruff, Terraform, Checkov, CodeQL, Gitleaks, Trivy, zizmor) is green | PASS | All checks green on `68cb528`, PR #52 |

## Critical workflows

Unit tests and `terraform test` mock AWS. They prove the logic and the state
machine wiring, not AWS authorization or service behavior.

| # | Workflow | Mocked evidence | Live evidence |
|---|---|---|---|
| W1 | Batch normalization; malformed findings recorded as rejected | `test_normalize_batch.py`, `workflow_contract` | Run 4 (2026-10-10) |
| W2 | Policy matching (type, generator, CVE, resource type, product, severity floor) | `test_policy.py`, `test_asff.py` | Runs 1-5 for type and generator, run 5 for `product`. CVE routing not live: it needs a real Inspector finding on a vulnerable instance, and it uses the same matcher |
| W3 | Guardrails: circuit breaker, rate limit, auto-trip, tag denylist, onboarding | `test_guardrails.py`, `test_check_guardrails.py` | Runs 2 and 5 |
| W4 | Approval: read-only GET, IAM POST, immutable decision, retry, timeout as deny | `test_approval_callback.py`, `test_decide.py`, `workflow_contract` | Runs 4 and 5 |
| W5 | **Approved actions recheck the breaker and tag** (new, S1) | 4 tests in `test_check_guardrails.py`; `workflow_contract` asserts the path and that only two states reach remediation | **Run 5**: blocked with the breaker set, executed with it clear |
| W6 | Six playbooks remediate real resources, including org mode | `test_playbook_*.py` | Runs 2-3, and run 5 for service-specific credentials (a Bedrock API key went `Inactive`) |
| W7 | Ledger, notifications, evidence export | `test_ledger.py`, `test_record_ledger.py` | Runs 2, 4 and 5 |
| W8 | Independent workflow alarms | `workflow_contract` (3 alarms) | Not live (ARCHITECTURE.md says so) |

Run 5 (2026-11-24) deployed the RC (`68cb528`, 141 resources) to the org-mode
hub and two member accounts in `us-east-1`, with no mocks, and then destroyed
it. Evidence: `docs/proof/run-5.json` and `docs/PROOF.md` run 5.

| # | Live criterion | Status | Evidence |
|---|---|---|---|
| L1a | A breaker set while an approval waits stops the approved playbook | PASS | HTTP 200 on Approve; ledger `blocked`, `circuit_breaker_paused`, approver ARN recorded; no automation ran |
| L1b | With the breaker clear, the approved playbook runs | PASS | Ledger `executed`; `RevokeRoleSessions` succeeded in member-a |
| L1c | `product` filter: the real GuardDuty finding matches; a self-imported copy does not | PASS | Sample matched `gd-product-check`; the copy under `product/<hub>/default` fell to `default`; importing under `product/aws/guardduty` was denied |
| L1d | Bedrock API key deactivated by `DisableCompromisedCredentials` | PASS | Access key and Bedrock key `Active` → `Inactive` after approval |
| L1e | Full teardown | PASS | `terraform destroy` removed 141 resources. Test user, keys, role, StackSet, queue and subscription deleted. No prefixed or tagged resources remain in any account. The signing secret is in its Secrets Manager recovery window |

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
| S5 | Policy matching was not bound to the finding's source. Anyone with `BatchImportFindings` in the deployment's account (or a member account, in org mode, for its own account) could trigger `auto` playbooks and approval requests | Medium | **FIXED** (owner chose the filter, 2026-11-24; live in run 5) | Optional `product` field on policy items (`aws/guardduty`, `aws/inspector`, `aws/securityhub`), matched against the finding's `ProductArn`. Every acting rule in `terraform.tfvars.example` sets it. `examples/org-mode` leaves it out because its live tests import findings. Tests: `test_policy.py`, `test_asff.py`. Run 5 confirmed that Security Hub assigns `<account>/default` to self-imported findings and refuses `product/aws/guardduty` |
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
- **Run 5 used `decide.py`'s `submit()` function** with the hub profile,
  as run 4 did, because the CLI's hidden prompt needs a person at the
  keyboard.
- **Next version is 2.0.0** because of the breaking approval API change.
