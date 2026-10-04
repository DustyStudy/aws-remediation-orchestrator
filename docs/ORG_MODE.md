# Org mode

One orchestrator for an AWS organization: it runs in the account that
receives everyone's findings and remediates in the account that owns the
resource.

Without org mode the orchestrator sees and fixes only its own account.

## How it works

```
member account                         hub account (Security Hub delegated admin)
--------------                         ------------------------------------------
finding ──▶ Security Hub ────────────▶ Security Hub ──▶ EventBridge ──▶ state machine
                                                                            │
tag check   ◀── assume member-guardrails-role ◀──────── check_guardrails ◀──┤
                                                                            │
SSM Automation ◀── assume member-execution-role ◀───── execute_remediation ◀┘
  runs the hub's shared document
  as the member's own playbook role
        │
        └── result ──▶ hub notifications topic
```

- **Findings.** A Security Hub delegated administrator receives its member
  accounts' findings, and EventBridge in that account emits an event for
  each. Deploy the orchestrator there and nothing else is needed for
  intake.
- **Playbooks.** The SSM Automation documents stay in the hub and are
  shared with the member accounts listed in `org_member_account_ids`. For
  a finding from a member, `execute_remediation` assumes
  `<name_prefix>-member-execution-role` in that account and starts the
  shared document there. The automation runs as the member account's own
  playbook role, so a playbook has the same permissions in every account
  and never more than its own account.
- **Guardrails.** The circuit breaker and rate limits stay in the hub and
  cover the whole organization. The `do-not-remediate` tag is read in the
  member account through `<name_prefix>-member-guardrails-role`.
- **Accounts that aren't onboarded.** The hub also receives findings from
  accounts it has no roles in, such as the management account. Those are
  recorded in the ledger as `blocked` with the reason
  `account_not_onboarded`, and nothing else happens.
- **Audit trail.** The ledger records the finding's account, and
  `export_evidence` writes one evidence document per account.

## Set it up

1. Deploy the orchestrator in the delegated administrator account with the
   member account IDs:

   ```hcl
   org_member_account_ids = ["111111111111", "222222222222"]
   ```

2. Apply `terraform/modules/playbook-roles` in each member account, with
   the values from the hub's `member_account_config` output:

   ```hcl
   module "remediation_playbook_roles" {
     source = "github.com/DustyStudy/aws-remediation-orchestrator//terraform/modules/playbook-roles"

     name_prefix            = "remediation-orchestrator"
     region                 = "us-east-1" # the hub's region
     notification_topic_arn = "<hub notification_topic_arn>"
     data_key_arn           = "<hub data_key_arn>"
     hub = {
       execute_remediation_role_arn = "<hub execute_remediation_role_arn>"
       check_guardrails_role_arn    = "<hub check_guardrails_role_arn>"
     }
   }
   ```

   [`examples/org-mode`](../examples/org-mode) does both steps for a hub
   and two members in one `terraform apply`. In a large organization, put
   the module in the account baseline pipeline instead.

## What the member roles allow

| Role (in the member account) | Trusted by | Can |
|---|---|---|
| `<prefix>-member-execution-role` | The hub's `execute_remediation` function role only | Start the hub's shared playbook documents, poll them, and pass the six playbook roles to SSM |
| `<prefix>-member-guardrails-role` | The hub's `check_guardrails` function role only | `tag:GetResources` |
| `<prefix>-*-automation-role` (six) | `ssm.amazonaws.com` | The same permissions as in the hub, scoped to the member account, plus publish to the hub's notifications topic |

The hub's topic policy and data key policy allow the member playbook
roles, and only those, to publish results.

## Limits

- **One region per deployment.** SSM documents are shared within a region,
  so a hub remediates in its own region in every account. Deploy a hub per
  region you want covered. If Security Hub aggregates other regions'
  findings into the hub's region, a playbook for one of them still runs in
  the hub's region, where a regional resource such as a security group
  doesn't exist, so expect it to fail.
- **Playbooks this deployment owns.** A document from
  `external_ssm_document_arns` is started in the member account as it is;
  sharing it and its role there is up to the deployment that owns it.
- **Explicit account list.** Documents are shared by account ID, so a new
  account needs adding to `org_member_account_ids` and the roles applying
  there. Until then its findings are recorded as `account_not_onboarded`.
- **The management account** is best left out. Its findings are then
  logged and never acted on.
