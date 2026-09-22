"""Scheduled step (not part of the state machine): turn the last period's
ledger entries into grc-evidence-automation-shaped evidence documents.

Runs on an EventBridge schedule (default: daily, see variables.tf
``evidence_export_schedule``) and writes one JSON document per
(account, region) pair that had activity in the period to S3, at
``s3://<bucket>/remediation-orchestrator/<date>/<account>-<region>.json``.
grc-evidence-automation (or any other consumer) can read that prefix the
same way it reads its own collectors' output.

Uses a table scan with a FilterExpression on execution_ts rather than a
GSI-backed query. That's fine at the volume a single organization's
Security Hub findings actually produce (low thousands/day at the high
end); if the ledger grows large enough for that to matter, add a GSI
keyed on a date-bucket attribute and query per bucket instead - noted as
the first place to optimize in docs/ARCHITECTURE.md.
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from remediation_common import ledger

_dynamodb = boto3.resource("dynamodb")
_s3 = boto3.client("s3")

LEDGER_TABLE_NAME = os.environ["LEDGER_TABLE_NAME"]
EVIDENCE_BUCKET_NAME = os.environ["EVIDENCE_BUCKET_NAME"]
LOOKBACK_HOURS = int(os.environ.get("LOOKBACK_HOURS", "24"))


def handler(_event: dict[str, Any], _context: Any) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    period_start = now - timedelta(hours=LOOKBACK_HOURS)
    items = _scan_ledger_since(period_start)

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        grouped[(item["account_id"], item["region"])].append(item)

    written_keys = []
    for (account_id, region), group_items in grouped.items():
        document = ledger.build_evidence_document(
            account_id=account_id,
            region=region,
            ledger_items=group_items,
            period_start=period_start.isoformat(),
            period_end=now.isoformat(),
        )
        key = f"remediation-orchestrator/{now:%Y-%m-%d}/{account_id}-{region}.json"
        _s3.put_object(
            Bucket=EVIDENCE_BUCKET_NAME,
            Key=key,
            Body=json.dumps(document, indent=2, default=str).encode("utf-8"),
            ContentType="application/json",
        )
        written_keys.append(key)

    return {"documents_written": written_keys, "ledger_items_processed": len(items)}


def _scan_ledger_since(period_start: datetime) -> list[dict[str, Any]]:
    table = _dynamodb.Table(LEDGER_TABLE_NAME)
    cutoff = period_start.isoformat()

    items: list[dict[str, Any]] = []
    scan_kwargs: dict[str, Any] = {
        "FilterExpression": "execution_ts >= :cutoff",
        "ExpressionAttributeValues": {":cutoff": cutoff},
    }
    while True:
        response = table.scan(**scan_kwargs)
        items.extend(response.get("Items", []))
        if "LastEvaluatedKey" not in response:
            break
        scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]
    return items
