# Approvals, failures and upgrades

## Submit a decision

1. Sign in to the designated approver profile with
   `aws sso login --profile approver`.
2. Review the finding, resource, account and playbook in the notification.
   Opening either link only displays the request.
3. From this repository, run `python scripts/decide.py --profile approver`.
   Paste the signed link at the hidden prompt, then type the decision to confirm.

The helper uses boto3/botocore from the existing requirements; it sends a
SigV4-signed POST, accepts only the standard HTTPS API Gateway decision endpoint,
and does not follow redirects. Signed links stay out of shell history.

The role needs an identity policy granting `execute-api:Invoke` on the
`approval_invoke_arn` Terraform output. Grant this narrowly to designated
approvers in the API's account. This module does not assign organization-wide
approval rights or modify Identity Center permission sets.

## Recover delivery

| Response | Action |
|---|---|
| 200 | Step Functions acknowledged the decision |
| 403 | Check the role permission, signed link and current session |
| 409 | The request is already resolved, expired during submission, or reserved for another decision/actor |
| 410 | Inspect execution history: the task expired or already closed; do not infer which decision won |
| 503 | Retry the same link using the same IAM session; the initial decision remains fixed |

Do not clear a reservation to try the opposite decision. A previous callback
may already have succeeded even when its response was lost. If the original
session is unavailable, investigate history and let the approval time out; start
a new reviewed execution only after confirming no remediation is in progress.

"The same IAM session" means the same assumed-role ARN, session name included.
Identity Center sessions use the sign-in name. A CLI profile that assumes a role
gets a new session name in every process, so set `role_session_name` in that
profile before submitting; a retry under a different name is treated as
another approver.

After a permission fix, expect 503 for several minutes. In the 2026-10-10 live
run a removed IAM deny kept applying to the callback for over four minutes.

## Respond to a workflow alarm

1. Locate the failed, timed-out or aborted execution in Step Functions.
2. Set the circuit breaker if repeated failures or unexpected actions are present.
3. Check completed Map iterations, the ledger and SSM automation history.
4. Resolve the dependency/permission error. Reconcile missing records from
   execution history before replaying only the unprocessed findings.
5. Confirm no duplicate playbook is running and restore processing.

CloudWatch metrics are an independent signal and can be delayed. Keep execution
history and CloudTrail accessible to incident responders. Test alarm delivery to
a confirmed subscription after deployment. Notifications can be repeated, and
a ledger outage can stop other unfinished findings in the same batch.

## Upgrade from email-click approvals

This changes the approval API and callback result format.

1. Pause new ingestion (disable the Security Hub EventBridge rule) and set the
   circuit breaker. The breaker alone does not stop ingestion.
2. Drain or explicitly stop existing executions, including pending approvals,
   before replacing the functions and state machine. Old executions retain their
   state-machine definition but call the same unversioned Lambda functions.
3. Review the Terraform plan. Existing Lambda/IAM resource addresses are
   preserved; the plan adds an IAM POST route and three alarms plus their
   notification permissions.
4. Grant the approver permission above and deploy. Run a sandbox approval and
   denial, verify the recorded actor, and test a two-finding batch.
5. Verify failure notifications, then restore ingestion and clear the breaker.

The pending-approval schema adds decision/actor attributes on submission; no
table replacement is needed. Its TTL remains 24 hours; choose an approval
timeout no longer than that. Waiting Map iterations count toward the five
active-finding limit.

## Verification

```sh
pip install --require-hashes -r requirements-dev.txt
pytest tests -q
ruff check terraform tests scripts
terraform -chdir=terraform init -backend=false
terraform -chdir=terraform validate
terraform -chdir=terraform test
```

The Terraform test uses mocked providers (Terraform 1.7+); it creates no AWS
resources. It checks batch routing, failure paths, actor routing, the IAM-only
submission route and independent alarms. Python regressions cover malformed
batches, read-only GETs, unauthenticated submissions, delivery retry, conflicting
decisions, closed tokens and stable ledger keys.

These checks are not a live deployment record. Run 4 in [PROOF.md](PROOF.md)
is the live record for the approval and batch paths; runs 1 to 3 are evidence
for their recorded versions.
