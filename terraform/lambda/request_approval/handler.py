"""State machine step (approval_required path): ask a human.

Invoked with the Step Functions ``waitForTaskToken`` pattern - this
function's own return value doesn't resume the state machine; only a
later ``SendTaskSuccess``/``SendTaskFailure`` call from
``approval_callback`` does (or the state's own timeout, if nobody ever
responds). This function's job is just to stash the task token and publish
the approve/deny links.

The signing secret is pulled from Secrets Manager per invocation (cached
per warm Lambda execution environment) rather than passed as a plaintext
environment variable, so it never shows up in the Lambda console's
environment-variable view or in `aws lambda get-function-configuration`.
"""
from __future__ import annotations

import os
import time
from typing import Any

import boto3
from remediation_common import approvals

_dynamodb = boto3.resource("dynamodb")
_sns = boto3.client("sns")
_secretsmanager = boto3.client("secretsmanager")

PENDING_APPROVALS_TABLE_NAME = os.environ["PENDING_APPROVALS_TABLE_NAME"]
NOTIFICATION_TOPIC_ARN = os.environ["NOTIFICATION_TOPIC_ARN"]
APPROVAL_BASE_URL = os.environ["APPROVAL_BASE_URL"]
SIGNING_SECRET_ARN = os.environ["SIGNING_SECRET_ARN"]

_secret_cache: dict[str, str] = {}


def _signing_secret() -> str:
    if "value" not in _secret_cache:
        response = _secretsmanager.get_secret_value(SecretId=SIGNING_SECRET_ARN)
        _secret_cache["value"] = response["SecretString"]
    return _secret_cache["value"]


def handler(event: dict[str, Any], _context: Any) -> None:
    finding = event["finding"]
    matched_policy = event["policy"]
    task_token = event["task_token"]

    approval_id = approvals.new_approval_id()
    secret = _signing_secret()

    item = approvals.build_pending_item(
        approval_id=approval_id,
        task_token=task_token,
        finding_id=finding["finding_id"],
        policy_id=matched_policy["match_id"],
        now=time.time(),
    )
    _dynamodb.Table(PENDING_APPROVALS_TABLE_NAME).put_item(Item=item)

    approve_sig = approvals.sign(approval_id, "approve", secret)
    deny_sig = approvals.sign(approval_id, "deny", secret)
    approve_url = f"{APPROVAL_BASE_URL}?approval_id={approval_id}&decision=approve&sig={approve_sig}"
    deny_url = f"{APPROVAL_BASE_URL}?approval_id={approval_id}&decision=deny&sig={deny_sig}"

    _sns.publish(
        TopicArn=NOTIFICATION_TOPIC_ARN,
        Subject=f"[approval required] {finding['title']}"[:100],
        Message=(
            f"A remediation needs approval before it runs.\n\n"
            f"Finding: {finding['title']}\n"
            f"Resource: {finding['resource_arn'] or finding['resource_type']}\n"
            f"Account: {finding['account_id']}  Region: {finding['region']}\n"
            f"Policy: {matched_policy['match_id']}  Action: {matched_policy.get('action_document')}\n"
            f"This request expires in 24 hours; if nobody responds, the finding is left unremediated.\n\n"
            f"Approve: {approve_url}\n"
            f"Deny:    {deny_url}\n"
        ),
    )
