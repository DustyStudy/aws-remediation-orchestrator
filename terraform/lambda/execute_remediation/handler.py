"""State machine step (auto/approved path): run the matched SSM Automation
document and wait for it to finish.

``action_document`` on the policy item can name a document this repo owns
(terraform/ssm-documents/*.tf) or one owned by another deployment entirely
- aws-cloud-security-toolbox's ``auto-remediate-open-ssh-rdp`` or
``ec2-isolation-runbook`` documents, for example - as long as this
function's execution role is granted ssm:StartAutomationExecution on that
document's ARN (see variables.tf: external_ssm_document_arns).

Polls get_automation_execution in-process rather than using a Step
Functions Wait+Choice loop. That's a deliberate scope cut: it's simpler
and correct for the automation documents this repo ships (all finish in
seconds), but it means a single Lambda invocation - bounded by
POLL_TIMEOUT_SECONDS, well under the Lambda time limit - is the ceiling on
how long a remediation can run. A playbook expected to take longer than
that should move to the Wait+Choice pattern instead; see the note in
docs/ARCHITECTURE.md.
"""
from __future__ import annotations

import os
import time
from typing import Any

import boto3

_ssm = boto3.client("ssm")

POLL_TIMEOUT_SECONDS = int(os.environ.get("POLL_TIMEOUT_SECONDS", "90"))
POLL_INTERVAL_SECONDS = float(os.environ.get("POLL_INTERVAL_SECONDS", "3"))

TERMINAL_STATUSES = {"Success", "Failed", "Cancelled", "TimedOut"}


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    finding = event["finding"]
    matched_policy = event["policy"]
    document_name = matched_policy["action_document"]

    parameters = _document_parameters(finding, document_name)

    start = _ssm.start_automation_execution(DocumentName=document_name, Parameters=parameters)
    execution_id = start["AutomationExecutionId"]

    status, deadline_hit = _poll_until_terminal(execution_id)

    return {
        "finding": finding,
        "policy": matched_policy,
        "execution_id": execution_id,
        "execution_status": status,
        "outcome": "executed" if status == "Success" else "failed",
        "deadline_hit": deadline_hit,
    }


def _document_parameters(finding: dict[str, Any], document_name: str) -> dict[str, list[str]]:
    """Every document this repo ships takes the same base parameter names;
    external documents may need their own mapping added here as they're
    adopted. Kept as an explicit dict rather than "pass the whole finding
    through" so each document's contract stays visible in code.
    """
    base = {
        "ResourceArn": [finding["resource_arn"]],
        "FindingId": [finding["finding_id"]],
    }
    if document_name.endswith("S3PublicAccessRemediation"):
        return base
    if document_name.endswith("DisableCompromisedCredentials"):
        return {**base, "AccountId": [finding["account_id"]]}
    return base


def _poll_until_terminal(execution_id: str) -> tuple[str, bool]:
    deadline = time.monotonic() + POLL_TIMEOUT_SECONDS
    status = "Pending"
    while time.monotonic() < deadline:
        response = _ssm.get_automation_execution(AutomationExecutionId=execution_id)
        status = response["AutomationExecution"]["AutomationExecutionStatus"]
        if status in TERMINAL_STATUSES:
            return status, False
        time.sleep(POLL_INTERVAL_SECONDS)
    return status, True
