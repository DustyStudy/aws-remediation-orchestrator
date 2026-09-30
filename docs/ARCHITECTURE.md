# Architecture

## Flow

```
Security Hub finding (GuardDuty / Config / Inspector / Macie / Access
Analyzer / third-party, all normalized to ASFF)
        │
        ▼
EventBridge rule (aws.securityhub, ACTIVE + NEW/NOTIFIED findings)
        │
        ▼
┌─────────────────────────── Step Functions: remediation-orchestrator ───────────────────────────┐
│                                                                                                   │
│  NormalizeFinding ──▶ CheckSkip ──▶ LookupPolicy ──▶ CheckGuardrails ──▶ GuardrailChoice         │
│  (parse ASFF)         (malformed/    (policy         (circuit breaker,    │                      │
│                        already-       registry        rate limit,        ├─ blocked ─▶ RecordBlocked
│                        triaged        match)          resource           │
│                        → skip)                        denylist)          ▼                      │
│                                                                       ModeChoice                 │
│                                                          ┌────────────────┼────────────────┐      │
│                                                          ▼                ▼                ▼      │
│                                                       ignore           dry_run      approval_required
│                                                          │                │                │      │
│                                                          ▼                ▼                ▼      │
│                                                    RecordIgnored   RecordDryRun    RequestApproval │
│                                                                                     (waitForTaskToken,│
│                                                                                      SNS email link) │
│                                                                                          │          │
│                                                          ┌───────────────────┬───────────┴──────┐   │
│                                                          ▼ approved          ▼ denied     ▼ timeout │
│                                                   ExecuteRemediation   RecordDenied   RecordDenied  │
│                                                   (SSM Automation,                                  │
│                                                    polled to                                        │
│                                                    completion)                                      │
│                                                          │                                          │
│                                                          ▼                                          │
│                                                   RecordExecuted / RecordExecutionFailed             │
│                                                                                                       │
└───────────────────────────────────────────────────────────────────────────────────────────────────┘
        │
        ▼
DynamoDB remediation-ledger (every path above ends here - full audit trail)
        │
        ▼ (scheduled)
export_evidence Lambda ──▶ S3 (grc-evidence-automation-shaped JSON)
```

Every terminal state calls `record_ledger`, including the no-op paths
(skipped, blocked, denied). The ledger is a complete decision log, not
just a log of actions taken - that distinction matters for both
debugging ("why didn't this fire?") and compliance evidence ("what did
the system decide, and why?").

## Component responsibilities

| Component | Responsibility |
|---|---|
| `normalize_finding` | Parse ASFF into the fields everything downstream needs |
| `lookup_policy` | Match the finding against the policy registry (DynamoDB), apply the matched policy's severity floor |
| `check_guardrails` | Circuit breaker, per-policy rate limit, resource tag denylist - see [POLICY_REGISTRY.md](POLICY_REGISTRY.md) |
| `request_approval` / `approval_callback` | Human-in-the-loop gate for `approval_required` policies, via `waitForTaskToken` and a signed one-click email link |
| `execute_remediation` | Starts and polls the policy's SSM Automation document |
| `record_ledger` | Writes the audit trail; publishes the result notification |
| `export_evidence` | Scheduled: rolls up the period's ledger entries into compliance evidence documents |

## Playbooks and other deployments

The repo owns six playbooks (`terraform/ssm-documents*.tf`). The
policy registry, not the playbook, decides whether each one runs
automatically, waits for approval, or only logs. A document owned by
another deployment can be added via `external_ssm_document_arns` (see
[POLICY_REGISTRY.md](POLICY_REGISTRY.md)), so every remediation goes
through the same policy decision, blast-radius controls and audit trail,
whichever repo built the playbook.

Findings from tools outside AWS enter through Security Hub too. The
optional `modules/wiz-finding-bridge` imports Wiz webhook deliveries as
ASFF findings with a `wiz/` generator id.

## Known limitations / deliberate scope cuts

These are documented trade-offs, not oversights - each one is called out
at the point in the code where it's made, and repeated here for
visibility:

- **Approval-link authentication.** The HMAC signature in an approval
  link proves the link wasn't tampered with, not who clicked it. Anyone
  who can read the SNS notification (everyone on a subscribed email
  list, for example) can approve or deny. Production use should front
  this with an identity-aware channel instead - Slack interactivity with
  workspace auth, or an API Gateway JWT/IAM authorizer - rather than
  relying on link secrecy alone. See
  `terraform/lambda/approval_callback/handler.py`.
- **In-process polling instead of a Wait+Choice loop.** `execute_remediation`
  polls `get_automation_execution` inside a single Lambda invocation
  (bounded by `POLL_TIMEOUT_SECONDS`) rather than using a Step Functions
  Wait state + Choice loop. Correct and simpler for the playbooks this
  repo ships (each makes a few API calls and finishes in seconds;
  snapshots are started, not awaited); a playbook expected to run
  long should move to the Wait+Choice pattern instead. See
  `terraform/lambda/execute_remediation/handler.py`.
- **Evidence export scans the ledger table** rather than querying a
  date-bucketed GSI. Fine at the finding volume a single organization's
  Security Hub actually produces; the first place to optimize if that
  changes. See `terraform/lambda/export_evidence/handler.py`.
- **One finding per Security Hub batch is processed.** Security Hub's
  `Findings - Imported` event can contain more than one finding;
  `normalize_finding` processes only the first. Fan-out (one Step
  Functions execution per finding in the batch, via an EventBridge
  Pipe or a fan-out Lambda ahead of the state machine) is the extension
  point if your finding volume needs every finding in a batch handled
  independently rather than relying on Security Hub re-delivering.
- **Policy registry match values need environment-specific tuning.**
  `terraform.tfvars.example`'s `match_field`/`match_value` pairs are
  illustrative, not guaranteed ASFF strings for every account - see the
  comment at the top of that file and [POLICY_REGISTRY.md](POLICY_REGISTRY.md).
