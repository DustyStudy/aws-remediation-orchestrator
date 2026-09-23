"""HTTP endpoint behind API Gateway: resolves an approve/deny click.

GET /decision?approval_id=...&decision=approve|deny&sig=...

Verifies the HMAC signature, checks the pending-approval item exists,
isn't expired, and hasn't already been consumed (a conditional delete
makes that check atomic against a double-click or a replayed link), then
calls SendTaskSuccess/SendTaskFailure on the stored Step Functions task
token.

Known limitation (documented in docs/ARCHITECTURE.md): the signature
proves the link wasn't tampered with, not who clicked it. Anyone who can
read the SNS notification (e.g. everyone on the subscribed email
distribution list) can approve or deny. Production use should front this
with an identity-aware channel - Slack interactivity with workspace auth,
or an API Gateway authorizer requiring SSO - instead of (or in addition
to) email links.
"""
from __future__ import annotations

import os
import time
from typing import Any

import boto3
from remediation_common import approvals

_dynamodb = boto3.resource("dynamodb")
_sfn = boto3.client("stepfunctions")
_secretsmanager = boto3.client("secretsmanager")

PENDING_APPROVALS_TABLE_NAME = os.environ["PENDING_APPROVALS_TABLE_NAME"]
SIGNING_SECRET_ARN = os.environ["SIGNING_SECRET_ARN"]

_secret_cache: dict[str, str] = {}


def _signing_secret() -> str:
    if "value" not in _secret_cache:
        response = _secretsmanager.get_secret_value(SecretId=SIGNING_SECRET_ARN)
        _secret_cache["value"] = response["SecretString"]
    return _secret_cache["value"]


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    params = event.get("queryStringParameters") or {}
    approval_id = params.get("approval_id", "")
    decision = params.get("decision", "")
    signature = params.get("sig", "")

    if decision not in ("approve", "deny"):
        return _response(400, "Invalid decision.")

    if not approvals.verify(approval_id, decision, signature, _signing_secret()):
        return _response(403, "Invalid or tampered approval link.")

    table = _dynamodb.Table(PENDING_APPROVALS_TABLE_NAME)
    item = table.get_item(Key={"approval_id": approval_id}).get("Item")
    if item is None:
        return _response(404, "Unknown or expired approval request.")
    if item.get("consumed"):
        return _response(409, "This approval request was already resolved.")
    if item.get("expires_at", 0) < time.time():
        return _response(410, "This approval request has expired.")

    try:
        # "consumed" is a DynamoDB reserved keyword (see the reserved-words
        # list); referencing it bare in an expression fails at parse time
        # with "Attribute name is a reserved keyword", not at the
        # condition-check step - so this always raised ValidationException,
        # never ConditionalCheckFailedException, and no approve/deny click
        # ever actually resolved a pending approval. Found by clicking a
        # real link end to end; see docs/PROOF.md.
        table.update_item(
            Key={"approval_id": approval_id},
            UpdateExpression="SET #consumed = :true",
            ConditionExpression="#consumed = :false",
            ExpressionAttributeNames={"#consumed": "consumed"},
            ExpressionAttributeValues={":true": True, ":false": False},
        )
    except _dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
        return _response(409, "This approval request was already resolved.")

    task_token = item["task_token"]
    if decision == "approve":
        _sfn.send_task_success(taskToken=task_token, output='{"decision": "approve"}')
        return _response(200, "Approved. The remediation will now run.")

    _sfn.send_task_failure(
        taskToken=task_token, error="ApprovalDenied", cause="Denied by approver."
    )
    return _response(200, "Denied. The remediation will not run.")


def _response(status_code: int, message: str) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "text/plain"},
        "body": message,
    }
