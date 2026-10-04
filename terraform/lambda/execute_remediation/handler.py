"""State machine step (auto/approved path): run the matched SSM Automation
document and wait for it to finish.

``action_document`` on the policy item can name a document this repo owns
(terraform/ssm-documents*.tf) or one owned by another deployment entirely,
as long as this function's execution role is granted
ssm:StartAutomationExecution on that document's ARN (see variables.tf:
external_ssm_document_arns).

Polls get_automation_execution in-process rather than using a Step
Functions Wait+Choice loop. That's a deliberate scope cut: it's simpler
and correct for the automation documents this repo ships (all finish in
seconds), but it means a single Lambda invocation - bounded by
POLL_TIMEOUT_SECONDS, well under the Lambda time limit - is the ceiling on
how long a remediation can run. A playbook expected to take longer than
that should move to the Wait+Choice pattern instead; see the note in
docs/ARCHITECTURE.md.

In org mode (MEMBER_EXECUTION_ROLE_NAME set) a finding from another account
runs its playbook in that account: this function assumes the member
execution role there and starts the hub's shared document by ARN. See
docs/ORG_MODE.md.
"""
from __future__ import annotations

import os
import time
from typing import Any

import boto3
from remediation_common import crossaccount

_ssm = boto3.client("ssm")
_sts = boto3.client("sts")

MEMBER_EXECUTION_ROLE_NAME = os.environ.get("MEMBER_EXECUTION_ROLE_NAME", "")

POLL_TIMEOUT_SECONDS = int(os.environ.get("POLL_TIMEOUT_SECONDS", "90"))
POLL_INTERVAL_SECONDS = float(os.environ.get("POLL_INTERVAL_SECONDS", "3"))

TERMINAL_STATUSES = {"Success", "Failed", "Cancelled", "TimedOut"}


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    finding = event["finding"]
    matched_policy = event["policy"]
    document_name = matched_policy["action_document"]

    parameters = _document_parameters(finding, document_name)

    ssm = _ssm
    member = crossaccount.member_client_kwargs(
        _sts, context.invoked_function_arn, finding.get("account_id", ""), MEMBER_EXECUTION_ROLE_NAME
    )
    if member:
        ssm = boto3.client("ssm", **member)
        document_name, parameters = _for_member_account(
            document_name, parameters, finding["account_id"], context.invoked_function_arn
        )

    start = ssm.start_automation_execution(DocumentName=document_name, Parameters=parameters)
    execution_id = start["AutomationExecutionId"]

    status, deadline_hit = _poll_until_terminal(ssm, execution_id)

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
        return {
            **base,
            "AccountId": [finding["account_id"]],
            "UserName": [finding.get("principal_user_name") or "unspecified"],
        }
    if document_name.endswith("RevokeRoleSessions"):
        return {
            **base,
            "AccountId": [finding["account_id"]],
            "RoleName": [finding.get("principal_role_name") or "unspecified"],
        }
    return base


def _for_member_account(
    document_name: str, parameters: dict[str, list[str]], account_id: str, function_arn: str
) -> tuple[str, dict[str, list[str]]]:
    """Point a playbook this deployment owns at a member account.

    A shared document has to be started by its full ARN, and its default
    AutomationAssumeRole is the hub's role, which SSM in the member account
    can't pass. modules/playbook-roles creates a role with the same name
    there, so the member's role ARN is the hub's with the account swapped.
    A document named by ARN belongs to another deployment and is started
    as it is; sharing it and its role with the member is that
    deployment's job.
    """
    if document_name.startswith("arn:"):
        return document_name, parameters

    _, partition, _, region, own_account = function_arn.split(":")[:5]
    described = _ssm.describe_document(Name=document_name)["Document"]
    for parameter in described.get("Parameters", []):
        if parameter["Name"] == "AutomationAssumeRole" and parameter.get("DefaultValue"):
            role_arn = parameter["DefaultValue"].replace(f"::{own_account}:", f"::{account_id}:")
            parameters = {**parameters, "AutomationAssumeRole": [role_arn]}

    return f"arn:{partition}:ssm:{region}:{own_account}:document/{document_name}", parameters


def _poll_until_terminal(ssm: Any, execution_id: str) -> tuple[str, bool]:
    deadline = time.monotonic() + POLL_TIMEOUT_SECONDS
    status = "Pending"
    while time.monotonic() < deadline:
        response = ssm.get_automation_execution(AutomationExecutionId=execution_id)
        status = response["AutomationExecution"]["AutomationExecutionStatus"]
        if status in TERMINAL_STATUSES:
            return status, False
        time.sleep(POLL_INTERVAL_SECONDS)
    return status, True
