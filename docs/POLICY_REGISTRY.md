# Policy registry

The policy registry is a DynamoDB table (`policy_registry_table_name`
output) that decides what happens to a Security Hub finding. Terraform
seeds it from `var.policy_registry_seed` (see
`terraform.tfvars.example`); you can also add or edit items directly in
the table for a break-glass change without a `terraform apply`.

## Item schema

| Field | Type | Meaning |
|---|---|---|
| `match_id` | string (key) | Unique id for the rule. `default` is required - it's the fallback applied when nothing else matches. |
| `match_field` | `"type_prefix"` \| `"generator_id"` | Which normalized finding field to match against. |
| `match_value` | string | Prefix to match. `""` on the `default` item (never actually matched against - see below). |
| `mode` | `"auto"` \| `"approval_required"` \| `"dry_run"` \| `"ignore"` | What happens on a match. |
| `action_document` | string | SSM Automation document name. Required for `auto`/`approval_required`. |
| `action_document_owner` | `"self"` \| `"external"` | Informational - documents which deployment owns the document. |
| `nist_controls` | list of string | NIST 800-53 control IDs this remediation addresses, carried into the audit ledger and evidence export. |
| `max_actions_per_hour` | number | Rate limit for this policy specifically (see `check_guardrails`). |
| `severity_threshold` | string or null | Minimum ASFF severity label (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`) to act on. Below it, the finding is treated as `ignore`. |
| `description` | string | Human-readable explanation, shown nowhere except the table itself - keep it useful for the next person editing this rule. |

## Matching

`lookup_policy` scans the full table (see
`terraform/lambda/lookup_policy/handler.py`) and picks the item whose
`match_value` is the longest prefix match against the finding's
`match_field`. The `default` item is excluded from that comparison and
used only as a fallback, so it's safe to leave its `match_value` empty -
it will never accidentally "win" a match against a real rule.

**Finding an accurate match value.** Security Hub's exact `Types` and
`GeneratorId` strings for a given finding depend on which product
produced it (GuardDuty, Config, a specific control) and aren't fully
predictable without live findings. Before relying on a new rule, confirm
the real value:

```bash
aws securityhub get-findings --max-results 5 \
  --filters '{"GeneratorId":[{"Value":"<substring>","Comparison":"CONTAINS"}]}'
```

This is why the seeded `default` policy is `dry_run`, not `auto` or
`ignore`: an unrecognized or mismatched finding gets logged to the
ledger for review, never silently dropped or silently acted on.

## Modes

- **`ignore`** - recorded in the ledger as `skipped`, nothing else happens.
- **`dry_run`** - recorded as `dry_run` with the policy/guardrail context
  that *would* have applied. No AWS API call is made against the
  resource. Good default while validating a new rule's match values.
- **`approval_required`** - an SNS notification with signed approve/deny
  links is sent; the state machine waits (up to
  `var.approval_timeout_seconds`, default 24h) for a response before
  recording `denied` (on explicit deny or on timeout) or proceeding to
  execution.
- **`auto`** - runs immediately, no human in the loop. Reserve for
  playbooks that are safe to run unattended - idempotent, and unable to
  make the situation worse if the finding turns out to be a false
  positive (re-blocking public S3 access is a good example; deactivating
  someone's access keys is not, hence that playbook's default is
  `approval_required`).

## Pointing a policy at a playbook this repo doesn't own

Set `action_document` to the full document name and add its ARN to
`var.external_ssm_document_arns` - that's what grants
`execute_remediation`'s IAM role permission to start it. For example, to
route open-SSH/RDP findings to `aws-cloud-security-toolbox`'s existing
`auto-remediate-open-ssh-rdp` playbook instead of building a new one:

```hcl
external_ssm_document_arns = [
  "arn:aws:ssm:us-east-1:123456789012:document/auto-remediate-open-ssh-rdp-RevokeOpenIngress",
]

policy_registry_seed = {
  # ... default, s3-public-access, guardduty-compromised-credentials ...

  open-ssh-rdp = {
    match_field           = "type_prefix"
    match_value           = "Software and Configuration Checks/Network Reachability"
    mode                  = "auto"
    action_document       = "auto-remediate-open-ssh-rdp-RevokeOpenIngress"
    action_document_owner = "external"
    nist_controls         = ["SC-7"]
    max_actions_per_hour  = 20
    severity_threshold    = "MEDIUM"
    description           = "Dispatches to aws-cloud-security-toolbox's existing SSH/RDP revocation playbook instead of duplicating it here."
  }
}
```

`execute_remediation`'s parameter mapping
(`terraform/lambda/execute_remediation/handler.py`, `_document_parameters`)
currently only special-cases the two documents this repo ships; an
external document with a different parameter contract than
`ResourceArn`/`FindingId` needs its own branch added there.
