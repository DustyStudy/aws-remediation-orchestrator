"""State machine step 2: match the finding against the policy registry.

Reads the whole policy-registry table (small - see docs/POLICY_REGISTRY.md
on why this doesn't need a GSI) and picks the most specific matching item,
falling back to the required "default" item. Also applies the matched
policy's severity floor: a finding below threshold is treated as an
ignore even if a policy otherwise matched, without needing a second policy
item just to express "and only if it's at least HIGH".
"""
from __future__ import annotations

import os
from typing import Any

import boto3
from remediation_common import asff, policy

_dynamodb = boto3.resource("dynamodb")
POLICY_TABLE_NAME = os.environ["POLICY_TABLE_NAME"]


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    finding = event["finding"]
    table = _dynamodb.Table(POLICY_TABLE_NAME)

    items: list[dict[str, Any]] = []
    scan_kwargs: dict[str, Any] = {}
    while True:
        response = table.scan(**scan_kwargs)
        items.extend(response.get("Items", []))
        if "LastEvaluatedKey" not in response:
            break
        scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]

    matched = policy.select_policy(items, finding)

    effective_mode = matched["mode"]
    if effective_mode != "ignore" and not asff.meets_severity_threshold(
        finding["severity_label"], matched.get("severity_threshold")
    ):
        matched = {**matched, "mode": "ignore"}

    return {"finding": finding, "policy": matched}
