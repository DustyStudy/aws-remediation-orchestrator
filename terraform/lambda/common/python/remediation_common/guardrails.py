"""Blast-radius controls evaluated before any remediation executes.

Three independent checks, any one of which can block an action:

1. **Circuit breaker** - a single SSM parameter that, when "true", pauses
   every remediation org-wide. This is the panic button: an operator (or
   the rate limiter below, automatically) can flip it without touching
   Terraform or redeploying anything.
2. **Rate limit** - a per-policy counter (DynamoDB, hour-bucketed) capping
   how many times a given playbook can fire in an hour. Guards against a
   noisy/misconfigured detector turning into a self-inflicted outage.
3. **Resource denylist** - any resource tagged ``do-not-remediate=true`` is
   skipped, checked generically via the Resource Groups Tagging API so it
   works across resource types without per-service code.

All three are pure functions of their inputs (clients passed in, not
constructed here) so they're unit-testable without hitting AWS.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

DENYLIST_TAG_KEY = "do-not-remediate"


@dataclass(frozen=True)
class GuardrailResult:
    allowed: bool
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"allowed": self.allowed, "reason": self.reason}


def check_circuit_breaker(ssm_client: Any, parameter_name: str) -> GuardrailResult:
    try:
        response = ssm_client.get_parameter(Name=parameter_name, WithDecryption=True)
        paused = response["Parameter"]["Value"].strip().lower() == "true"
    except ssm_client.exceptions.ParameterNotFound:
        paused = False
    if paused:
        return GuardrailResult(allowed=False, reason="circuit_breaker_paused")
    return GuardrailResult(allowed=True)


def trip_circuit_breaker(ssm_client: Any, parameter_name: str, kms_key_id: str) -> None:
    """Flip the circuit breaker on. Called by the rate limiter when a
    policy's rate limit is exceeded by a wide enough margin to suggest a
    detector storm rather than ordinary noise (see check_rate_limit)."""
    ssm_client.put_parameter(
        Name=parameter_name,
        Value="true",
        Type="SecureString",
        KeyId=kms_key_id,
        Overwrite=True,
    )


def check_rate_limit(
    dynamodb_client: Any,
    table_name: str,
    policy_id: str,
    max_per_hour: int,
    now: float | None = None,
) -> GuardrailResult:
    """Atomically increment this hour's counter for ``policy_id`` and
    compare against ``max_per_hour``. Uses a conditional update so
    concurrent executions can't both squeak in over the limit.
    """
    now = time.time() if now is None else now
    hour_bucket = int(now // 3600)
    counter_key = f"{policy_id}#{hour_bucket}"
    ttl = int(now) + 7200  # counters self-expire two hours after their bucket

    try:
        response = dynamodb_client.update_item(
            TableName=table_name,
            Key={"counter_key": {"S": counter_key}},
            UpdateExpression="SET #c = if_not_exists(#c, :zero) + :one, #ttl = :ttl",
            ConditionExpression="attribute_not_exists(#c) OR #c < :max",
            ExpressionAttributeNames={"#c": "count", "#ttl": "expires_at"},
            ExpressionAttributeValues={
                ":zero": {"N": "0"},
                ":one": {"N": "1"},
                ":max": {"N": str(max_per_hour)},
                ":ttl": {"N": str(ttl)},
            },
            ReturnValues="UPDATED_NEW",
        )
    except dynamodb_client.exceptions.ConditionalCheckFailedException:
        return GuardrailResult(allowed=False, reason="rate_limit_exceeded")

    count = int(response["Attributes"]["count"]["N"])
    return GuardrailResult(allowed=True, reason=f"count={count}/{max_per_hour}")


def check_resource_denylist(tagging_client: Any, resource_arn: str) -> GuardrailResult:
    if not resource_arn:
        return GuardrailResult(allowed=True)
    response = tagging_client.get_resources(ResourceARNList=[resource_arn])
    for mapping in response.get("ResourceTagMappingList", []):
        for tag in mapping.get("Tags", []):
            if tag.get("Key") == DENYLIST_TAG_KEY and tag.get("Value", "").lower() == "true":
                return GuardrailResult(allowed=False, reason="resource_tagged_do_not_remediate")
    return GuardrailResult(allowed=True)
