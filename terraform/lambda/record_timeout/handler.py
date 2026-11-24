"""Record the findings a timed-out execution left without a ledger item.

Step Functions stops a timed-out execution without running any catch
state, so findings still in the Map (most often waiting for approval) would
have no ledger item. EventBridge invokes this function with the execution's
status change event. It normalizes the execution's input exactly as
``normalize_finding`` did, and writes a ``timed_out`` item for each finding
that has no ledger item from the execution's lifetime.

The item key is the finding and the execution's stop time, and the write
is conditional, so a redelivered event writes nothing twice.
"""
from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from remediation_common import batch, ledger

_dynamodb = boto3.resource("dynamodb")
_sfn = boto3.client("stepfunctions")

LEDGER_TABLE_NAME = os.environ["LEDGER_TABLE_NAME"]
STATE_MACHINE_ARN = os.environ["STATE_MACHINE_ARN"]


def _iso(epoch_ms: int, *, millis: bool = True) -> str:
    moment = datetime.fromtimestamp(epoch_ms / 1000, tz=UTC)
    if millis:
        return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"
    return moment.strftime("%Y-%m-%dT%H:%M:%S")


def _execution_input(detail: dict[str, Any]) -> dict[str, Any]:
    raw = detail.get("input")
    if raw is None:
        # The event omits inputs over its size limit; history keeps them.
        raw = _sfn.describe_execution(executionArn=detail["executionArn"])["input"]
    return json.loads(raw)


def _recorded_during(table: Any, finding_id: str, start: str, stop: str) -> bool:
    response = table.query(
        KeyConditionExpression=Key("finding_id").eq(finding_id) & Key("execution_ts").between(start, stop),
        Limit=1,
    )
    return bool(response.get("Items"))


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    detail = event.get("detail") or {}
    if detail.get("status") != "TIMED_OUT" or detail.get("stateMachineArn") != STATE_MACHINE_ARN:
        return {"recorded": [], "already_recorded": [], "ignored": True}

    execution_arn = detail["executionArn"]
    timestamp = _iso(detail["stopDate"])
    # Ledger timestamps are Step Functions EnteredTime values. Widen the
    # window by a second on each side so formatting differences can't hide one.
    window_start = _iso(detail["startDate"] - 1000, millis=False)
    window_stop = _iso(detail["stopDate"] + 1000, millis=False)

    table = _dynamodb.Table(LEDGER_TABLE_NAME)
    recorded, already = [], []
    for item in batch.normalize_event(_execution_input(detail)):
        finding = item["finding"]
        if _recorded_during(table, finding["finding_id"], window_start, window_stop):
            already.append(finding["finding_id"])
            continue
        ledger_item = ledger.build_ledger_item(
            finding=finding,
            policy={"match_id": "n/a", "mode": "n/a"},
            guardrail_result={"allowed": None, "reason": "execution_timed_out"},
            outcome="timed_out",
            decided_by="system",
            execution_id=None,
            execution_status="TIMED_OUT",
            timestamp=timestamp,
        )
        ledger_item["workflow_execution_arn"] = execution_arn
        try:
            table.put_item(
                Item=ledger_item,
                ConditionExpression="attribute_not_exists(finding_id)",
            )
        except ClientError as error:
            if error.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise
            already.append(finding["finding_id"])
            continue
        recorded.append(finding["finding_id"])
    return {"recorded": recorded, "already_recorded": already, "ignored": False}
