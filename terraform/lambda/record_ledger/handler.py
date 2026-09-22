"""Terminal state machine step: write the ledger item and publish a notice.

Runs on every path out of the state machine (skipped, blocked, dry-run,
denied, executed, failed) - see docs/ARCHITECTURE.md for the full diagram.
``event["outcome"]`` is set by whichever prior step the execution came
from; this function's only job is to persist it and notify, never to
decide it.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import boto3
from remediation_common import ledger

_dynamodb = boto3.resource("dynamodb")
_sns = boto3.client("sns")

LEDGER_TABLE_NAME = os.environ["LEDGER_TABLE_NAME"]
NOTIFICATION_TOPIC_ARN = os.environ["NOTIFICATION_TOPIC_ARN"]


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    finding = event["finding"]
    matched_policy = event.get("policy", {"match_id": "n/a", "mode": "n/a"})
    guardrail_result = event.get("guardrail_result", {"allowed": None, "reason": None})
    outcome = event["outcome"]
    decided_by = event.get("decided_by", "system")
    execution_id = event.get("execution_id")
    execution_status = event.get("execution_status")

    timestamp = datetime.now(timezone.utc).isoformat()

    item = ledger.build_ledger_item(
        finding=finding,
        policy=matched_policy,
        guardrail_result=guardrail_result,
        outcome=outcome,
        decided_by=decided_by,
        execution_id=execution_id,
        execution_status=execution_status,
        timestamp=timestamp,
    )

    table = _dynamodb.Table(LEDGER_TABLE_NAME)
    table.put_item(Item=item)

    _sns.publish(
        TopicArn=NOTIFICATION_TOPIC_ARN,
        Subject=f"[{outcome}] {finding['title']}"[:100],
        Message=(
            f"Finding: {finding['title']}\n"
            f"Resource: {finding['resource_arn'] or finding['resource_type']}\n"
            f"Account: {finding['account_id']}  Region: {finding['region']}\n"
            f"Policy: {matched_policy.get('match_id')}  Mode: {matched_policy.get('mode')}\n"
            f"Outcome: {outcome}\n"
            f"Guardrail: {guardrail_result.get('reason') or 'ok'}\n"
            f"Execution: {execution_id or 'n/a'} ({execution_status or 'n/a'})\n"
        ),
    )

    return {"ledger_item": item}
