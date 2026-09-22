"""State machine step 3: blast-radius guardrails.

Runs all three checks from remediation_common.guardrails even if an
earlier one already fails, so the ledger entry (written later, from
``guardrail_result``) always shows the full picture rather than just
whichever check happened to run first - useful when debugging why a
finding wasn't acted on.

If the rate limit is blown by more than ``CIRCUIT_BREAKER_MULTIPLIER``x its
threshold, trips the org-wide circuit breaker: that's the signal a
detector is storming rather than a policy just needing a higher limit.
"""
from __future__ import annotations

import os
from typing import Any

import boto3
from remediation_common import guardrails

_ssm = boto3.client("ssm")
_dynamodb = boto3.client("dynamodb")
_tagging = boto3.client("resourcegroupstaggingapi")

PAUSE_PARAMETER_NAME = os.environ["PAUSE_PARAMETER_NAME"]
PAUSE_PARAMETER_KMS_KEY_ID = os.environ["PAUSE_PARAMETER_KMS_KEY_ID"]
RATE_LIMIT_TABLE_NAME = os.environ["RATE_LIMIT_TABLE_NAME"]
CIRCUIT_BREAKER_MULTIPLIER = float(os.environ.get("CIRCUIT_BREAKER_MULTIPLIER", "3"))


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    finding = event["finding"]
    matched_policy = event["policy"]

    breaker = guardrails.check_circuit_breaker(_ssm, PAUSE_PARAMETER_NAME)

    max_per_hour = int(matched_policy.get("max_actions_per_hour", 10))
    rate = guardrails.check_rate_limit(
        _dynamodb, RATE_LIMIT_TABLE_NAME, matched_policy["match_id"], max_per_hour
    )
    if not rate.allowed and rate.reason == "rate_limit_exceeded":
        _maybe_trip_breaker(matched_policy["match_id"], max_per_hour)

    denylist = guardrails.check_resource_denylist(_tagging, finding["resource_arn"])

    allowed = breaker.allowed and rate.allowed and denylist.allowed
    reasons = [r.reason for r in (breaker, rate, denylist) if not r.allowed and r.reason]

    return {
        "finding": finding,
        "policy": matched_policy,
        "guardrail_result": {
            "allowed": allowed,
            "reason": "; ".join(reasons) if reasons else None,
            "circuit_breaker": breaker.to_dict(),
            "rate_limit": rate.to_dict(),
            "denylist": denylist.to_dict(),
        },
    }


def _maybe_trip_breaker(policy_id: str, max_per_hour: int) -> None:
    """Best-effort: a second rate-limit read to see how far over we are.
    Never blocks the guardrail decision above if this fails.
    """
    try:
        over_by = guardrails.check_rate_limit(
            _dynamodb, RATE_LIMIT_TABLE_NAME, policy_id, max_per_hour * 1000
        )
        count = int((over_by.reason or "count=0").split("=")[1].split("/")[0])
        if count >= max_per_hour * CIRCUIT_BREAKER_MULTIPLIER:
            guardrails.trip_circuit_breaker(_ssm, PAUSE_PARAMETER_NAME, PAUSE_PARAMETER_KMS_KEY_ID)
    except Exception:  # noqa: BLE001 - guardrail tripping must never block the guardrail decision itself
        print(f"WARN: circuit-breaker check for policy {policy_id!r} failed, leaving breaker as-is")
