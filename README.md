# aws-remediation-orchestrator

[![Lint and Security Scan](https://github.com/DustyStudy/aws-remediation-orchestrator/actions/workflows/lint-and-scan.yml/badge.svg)](https://github.com/DustyStudy/aws-remediation-orchestrator/actions/workflows/lint-and-scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![AWS](https://img.shields.io/badge/AWS-Commercial%20%2B%20GovCloud-orange)](#)

An event-driven engine that turns AWS Security Hub findings into
**governed, auditable** remediation - policy-driven routing, blast-radius
guardrails, a human approval gate for disruptive actions, and a
compliance-evidence export - built on Step Functions, Lambda, and SSM
Automation. Every ARN is partition-aware (`data.aws_partition`), so it
runs in both AWS commercial and GovCloud.

## Why this exists, and how it relates to aws-cloud-security-toolbox

[`aws-cloud-security-toolbox`](https://github.com/DustyStudy/aws-cloud-security-toolbox)
is a library of independent remediation templates: each one detects and
fixes one specific thing, deployed standalone, with no shared policy
layer, approval gate, or audit trail across playbooks.

This repo is the governance layer above that. Every Security Hub finding
flows through one pipeline, where a **policy registry** - not each
playbook's own code - decides whether a match runs automatically, waits
for a human, only logs what it would do, or is ignored entirely; a
**circuit breaker and per-policy rate limit** cap how much damage a
misconfigured detector (or this system itself) can do; and every
decision - acted on or not - lands in an **audit ledger** that exports as
compliance evidence. It owns two playbooks directly and can dispatch to
a playbook owned by another deployment (including the toolbox's own) via
`external_ssm_document_arns`. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full picture.

## Architecture

```
Security Hub finding
        │
        ▼
EventBridge  ──▶  Step Functions (normalize → match policy → check
                   guardrails → route by mode → execute/approve/dry-run)
                        │
                        ▼
              DynamoDB audit ledger  ──(scheduled)──▶  S3 compliance evidence
```

Full diagram, state-by-state, in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## What's in the box

| Piece | What it does |
|---|---|
| **Policy registry** (DynamoDB) | Matches a finding's ASFF type/generator against rules that set mode, target playbook, NIST 800-53 mapping, and rate limit. See [`docs/POLICY_REGISTRY.md`](docs/POLICY_REGISTRY.md). |
| **Guardrails** | Org-wide circuit breaker (one SSM parameter), per-policy hourly rate limit with auto-trip on a detector storm, and a generic `do-not-remediate` resource tag denylist (Resource Groups Tagging API - works across resource types with no per-service code). |
| **Approval flow** | `approval_required` policies pause the state machine (`waitForTaskToken`) and email signed one-click approve/deny links; a timeout with no response is treated as a deny. |
| **Remediation execution** | Starts the policy's SSM Automation document and polls it to completion. |
| **Audit ledger** (DynamoDB) | One record per execution outcome - skipped, blocked, denied, dry-run, executed, or failed - with the guardrail result and NIST control mapping that produced it. |
| **Evidence export** (S3, scheduled) | Rolls the ledger up into [`grc-evidence-automation`](https://github.com/DustyStudy/grc-evidence-automation)-shaped JSON documents. See [`docs/EVIDENCE_SCHEMA.md`](docs/EVIDENCE_SCHEMA.md). |
| **Two owned playbooks** | `S3PublicAccessRemediation` (auto: re-applies Block Public Access) and `DisableCompromisedCredentials` (approval-required: deactivates an IAM user's active access keys on a GuardDuty finding). |

## Deploying

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # then edit match values - see docs/POLICY_REGISTRY.md
terraform init
terraform plan
terraform apply
```

Requires Terraform >= 1.5 and the `hashicorp/aws` provider >= 5.0.
Security Hub must already be enabled in the target account/region for
the EventBridge rule to receive anything.

## Testing

```bash
pip install -r requirements-dev.txt
pytest tests/ -q          # unit tests for the shared remediation_common package
ruff check terraform tests
```

CI (`.github/workflows/lint-and-scan.yml`) runs pytest/ruff, plus
`terraform fmt`/`validate`/`tflint`/Checkov, on every push and PR.

## Repository layout

```
aws-remediation-orchestrator/
├── terraform/
│   ├── lambda/
│   │   ├── common/python/remediation_common/  # shared logic, packaged as a Lambda layer
│   │   ├── normalize_finding/  lookup_policy/  check_guardrails/
│   │   ├── request_approval/   approval_callback/  execute_remediation/
│   │   └── record_ledger/      export_evidence/
│   ├── ssm-documents/           # the two playbooks this repo owns + their inline scripts
│   ├── stepfunctions.tf         # the state machine definition
│   ├── eventbridge.tf           # Security Hub ingestion
│   ├── api-gateway.tf           # approval callback endpoint
│   ├── dynamodb.tf              # policy registry, rate limits, pending approvals, ledger
│   ├── kms-data.tf / lambda-common.tf / secrets.tf / s3.tf / ssm-parameter.tf
│   └── terraform.tfvars.example
├── tests/                       # pytest unit tests for remediation_common
└── docs/
    ├── ARCHITECTURE.md
    ├── POLICY_REGISTRY.md
    └── EVIDENCE_SCHEMA.md
```

## License

[MIT](LICENSE)
