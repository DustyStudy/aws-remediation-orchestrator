# wiz-finding-bridge

Receives Wiz webhook deliveries through an API Gateway HTTP API. Each
delivery is imported into Security Hub as an ASFF finding, so it reaches
the orchestrator's state machine through the same EventBridge rule as
every other finding. An SNS notification with the raw payload goes out
too.

The root module deploys this when `enable_wiz_finding_bridge = true`. It
can also be used on its own (`source = "./modules/wiz-finding-bridge"`)
if you want to set the field-path variables below.

**Before you choose this module:** if your Wiz tenant can send issues to
Security Hub natively, use that instead. It gives you the same entry
into the orchestrator without a webhook endpoint to run. This module is
for tenants where the plain Webhook integration is the option available.

## Read this before you deploy

This module is **schema-tolerant, not schema-assuming**. Wiz's outbound
webhook JSON shape isn't something verifiable from outside a live Wiz
tenant, and it's not something this repo asserts to know precisely. So
rather than hardcode field names that might be subtly wrong (and fail
silently), the Lambda:

- Reads which fields to treat as severity/title/resource from
  **dot-notation paths you configure** (`severity_field_path`,
  `title_field_path`, `resource_field_path`), not hardcoded keys.
- **Always includes the raw payload** (truncated to 2000 characters) in
  the SNS message, so your first real finding tells you exactly what the
  actual field names are.
- **Fails open on an unresolved severity** — if `severity_field_path`
  doesn't resolve to anything, the finding is still forwarded (marked
  "unresolved") rather than silently dropped below the threshold.

Plan on deploying this, sending one real test finding, reading the raw
payload in the SNS message, and then updating `severity_field_path` /
`title_field_path` / `resource_field_path` to match. That's the intended
workflow, not a workaround.

The defaults above (`severity`, `title`, `primaryResource`) are set from
a real Wiz **Detection** payload (a Defend/threat-hunting event —
`mitreTactics`, `tdrSource`, `threatId`), not a guess. `severity` and
`title` are top-level strings in that shape; `primaryResource` is a
nested object whose internal fields weren't visible, so it's rendered as
JSON in the report rather than assumed into a sub-path. A Wiz **Issue**
(the CSPM misconfiguration findings — e.g. a security group open to the
internet) may use a different shape than a Detection; if your findings
come from Issues rather than Detections, treat these defaults as a
starting point to verify against your own first real delivery, not a
guarantee.

## How authentication works

As of this writing, Wiz's basic Webhook integration (Settings →
Integrations → **+ Add Integration** → **Webhook**) only lets you
configure a destination **URL** — no custom headers, no payload signing.
So instead of verifying a signature header, this module generates a long
random secret and expects it as the **last path segment of the webhook
URL itself** (`.../wiz-webhook/<secret>`) — the same "unguessable URL"
pattern most URL-only webhook integrations rely on. The secret lives in
Secrets Manager, never in state as plaintext beyond what Terraform state
already contains for any managed secret.

If your Wiz tenant's integration options have since added header-based
signing, that would be a stronger mechanism than this — check your Wiz
console before relying solely on the secret-in-URL approach for anything
particularly sensitive.

## Using Terraform

```hcl
module "remediation_orchestrator" {
  source = "github.com/DustyStudy/aws-remediation-orchestrator//terraform"

  enable_wiz_finding_bridge = true
  # ...
}
```

Then retrieve the generated secret and build the full webhook URL:

```bash
terraform output -raw wiz_webhook_url_base

aws secretsmanager get-secret-value \
  --secret-id "$(terraform output -raw wiz_webhook_secret_arn)" \
  --query SecretString --output text
```

Paste `<wiz_webhook_url_base>/wiz-webhook/<secret>` into Wiz's Webhook
integration URL field. Then create an **Automation Rule** (Policies →
Automation Rules → **+ Add Rule**) with a "When" condition like *Issue
Created* (or *Detection Created*, if you have Wiz Defend), an optional
severity "If" filter, and set the action to send to the webhook
integration you just created.

**Rotating the token:** if the URL may have leaked, replace the secret
value in Secrets Manager and re-paste the new URL into Wiz. The Lambda
caches the secret for `SECRET_CACHE_TTL_SECONDS` (default 300), so the old
token stops being accepted within about five minutes without redeploying.

Works the same in GovCloud — HTTP APIs are fully supported there; only
edge-optimized endpoints and private VPC-link integrations have GovCloud
caveats, and this module uses neither.

## How findings reach the orchestrator

Each accepted delivery at or above `minimum_severity` becomes one ASFF
finding in this account's Security Hub `default` product:

| ASFF field | Value |
|---|---|
| `Id` | `wiz/<value at id_field_path>`, or `wiz/<sha256 of the payload>` if that doesn't resolve |
| `GeneratorId` | `wiz/<title>` |
| `Types` | `["Software and Configuration Checks/Wiz"]` |
| `Severity.Label` | the resolved severity, or `INFORMATIONAL` if it isn't a valid label |
| `Resources[0]` | `Type = "Other"`, `Id` = the value at `resource_id_field_path`, or `wiz-unresolved-resource` |

In the policy registry, match these with `match_field = "generator_id"`
and a `match_value` of `wiz/` (every Wiz finding) or `wiz/<rule title>`
(one rule). A playbook needs `Resources[0].Id` to be the AWS ARN of the
resource, so set `resource_id_field_path` before routing Wiz findings to
anything but `dry_run`. Findings with a placeholder resource id skip the
`do-not-remediate` tag check, because the tagging API only accepts ARNs.

A failed import is logged, and the SNS message says so. The delivery
still gets a `200`, so Wiz doesn't retry into the same failure.

## Variables

| Variable | Description | Default |
|---|---|---|
| `name_prefix` | Prefix for all resource names | `wiz-finding-bridge` |
| `notification_email` | Email to subscribe to the SNS topic | `""` (no subscription) |
| `minimum_severity` | Lowest severity to import and notify on | `HIGH` |
| `severity_field_path` | Dot-notation path to the severity field | `severity` |
| `title_field_path` | Dot-notation path to the title field | `title` |
| `resource_field_path` | Dot-notation path to the resource field shown in notifications | `primaryResource` |
| `resource_id_field_path` | Dot-notation path to the resource's ARN, used as `Resources[0].Id` | `""` (placeholder id) |
| `id_field_path` | Dot-notation path to Wiz's issue id, for stable finding ids | `id` |
| `throttle_burst_limit` / `throttle_rate_limit` | API Gateway throttle settings | `10` / `5` |
| `code_signing_config_arn` | ARN of an existing `aws_lambda_code_signing_config` to enforce | `null` |

## Notes

- **No WAF in this module.** The endpoint is protected by the
  unguessable secret path segment plus stage-level throttling, not a
  network ACL. If you want IP-reputation filtering or rate-limiting
  beyond the built-in throttle settings, associate an
  `aws_wafv2_web_acl` with the stage separately via
  `aws_wafv2_web_acl_association` — left out here to keep the module
  focused, not because it wouldn't help.
- The API Gateway access log intentionally excludes the request body
  (finding details can be sensitive) — only request metadata is logged.
  The Lambda's own CloudWatch logs will contain finding content, so
  their log group is KMS-encrypted.
- A malformed or unauthenticated delivery always gets a fast HTTP
  response (`401` for a bad secret, `200` for a bad body) so Wiz doesn't
  pile up retries against a dead endpoint.
- This module needs the `random` and `archive` Terraform providers in
  addition to `aws` — see `versions.tf`.
