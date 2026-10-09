"""GET reviews a link; an IAM-authenticated POST submits an immutable decision.

Only acknowledged delivery is marked consumed. The same actor can retry the
same decision; Step Functions' single-use token arbitrates completion.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from remediation_common import approvals

_dynamodb = boto3.resource("dynamodb")
_sfn = boto3.client("stepfunctions")
_secretsmanager = boto3.client("secretsmanager")
PENDING_APPROVALS_TABLE_NAME = os.environ["PENDING_APPROVALS_TABLE_NAME"]
SIGNING_SECRET_ARN = os.environ["SIGNING_SECRET_ARN"]
_secret_cache: dict[str, str] = {}


def _signing_secret() -> str:
    if "value" not in _secret_cache:
        _secret_cache["value"] = _secretsmanager.get_secret_value(
            SecretId=SIGNING_SECRET_ARN
        )["SecretString"]
    return _secret_cache["value"]


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    context = event.get("requestContext") or {}
    method = context.get("http", {}).get("method")
    if method not in ("GET", "POST"):
        return _response(405, "Use GET to review or an IAM-authenticated POST to decide.")
    actor = (context.get("authorizer") or {}).get("iam", {}).get("userArn")
    if method == "POST" and not actor:
        return _response(403, "An IAM-authenticated approver is required.")

    params = event.get("queryStringParameters") or {}
    approval_id = params.get("approval_id", "")
    decision = params.get("decision", "")
    signature = params.get("sig", "")
    if decision not in ("approve", "deny"):
        return _response(400, "Invalid decision.")
    if not approvals.verify(approval_id, decision, signature, _signing_secret()):
        return _response(403, "Invalid or tampered approval link.")

    table = _dynamodb.Table(PENDING_APPROVALS_TABLE_NAME)
    item = table.get_item(Key={"approval_id": approval_id}, ConsistentRead=True).get("Item")
    if item is None:
        return _response(404, "Unknown or expired approval request.")
    if item.get("consumed"):
        return _response(409, "This approval request was already resolved.")
    if item.get("expires_at", 0) <= time.time():
        return _response(410, "This approval request has expired.")
    if method == "GET":
        return _response(200, (
            f"Review decision: {decision}\nFinding: {item['finding_id']}\n"
            f"Policy: {item['policy_id']}\n\nNo decision has been submitted.\n"
            "Submit this URL with an IAM-signed POST using scripts/decide.py. "
            "Your role needs execute-api:Invoke on the POST /decision route."
        ))

    try:
        # Never unlock a decision after an ambiguous network response.
        table.update_item(
            Key={"approval_id": approval_id},
            UpdateExpression="SET #decision = :decision, decided_by = :actor",
            ConditionExpression=(
                "#consumed = :false AND expires_at > :now AND "
                "(attribute_not_exists(#decision) OR (#decision = :decision AND decided_by = :actor))"
            ),
            ExpressionAttributeNames={"#consumed": "consumed", "#decision": "decision"},
            ExpressionAttributeValues={
                ":false": False, ":now": int(time.time()), ":decision": decision, ":actor": actor,
            },
        )
    except _dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
        return _response(409, "Request expired, resolved, or reserved by another decision/approver.")

    try:
        # Return denials as structured results too, retaining the actor.
        _sfn.send_task_success(
            taskToken=item["task_token"],
            output=json.dumps({"decision": decision, "decided_by": actor}),
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("TaskTimedOut", "TaskDoesNotExist", "InvalidToken"):
            return _response(410, "Task is closed or expired; inspect execution history for its outcome.")
        return _response(503, "Delivery not confirmed. Retry the same decision with the same IAM session.")
    except BotoCoreError:
        return _response(503, "Delivery not confirmed. Retry the same decision with the same IAM session.")

    try:
        table.update_item(
            Key={"approval_id": approval_id},
            UpdateExpression="SET #consumed = :true",
            ConditionExpression="#decision = :decision AND decided_by = :actor",
            ExpressionAttributeNames={"#consumed": "consumed", "#decision": "decision"},
            ExpressionAttributeValues={":true": True, ":decision": decision, ":actor": actor},
        )
    except (ClientError, BotoCoreError):
        # The token cannot be reused even if this bookkeeping write fails.
        print("WARN: approval delivered; pending-item acknowledgement failed")
    return _response(200, f"Decision delivered: {decision}.")


def _response(status_code: int, message: str) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff",
        },
        "body": message,
    }
