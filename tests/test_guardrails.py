from unittest.mock import MagicMock

import pytest
from remediation_common import guardrails


class FakeParameterNotFound(Exception):
    pass


class FakeConditionalCheckFailed(Exception):
    pass


def make_ssm_client(*, paused=None, raise_not_found=False):
    client = MagicMock()
    client.exceptions.ParameterNotFound = FakeParameterNotFound
    if raise_not_found:
        client.get_parameter.side_effect = FakeParameterNotFound()
    else:
        client.get_parameter.return_value = {"Parameter": {"Value": paused}}
    return client


def make_dynamodb_client(*, count_after_update=None, raise_conditional_failed=False):
    client = MagicMock()
    client.exceptions.ConditionalCheckFailedException = FakeConditionalCheckFailed
    if raise_conditional_failed:
        client.update_item.side_effect = FakeConditionalCheckFailed()
    else:
        client.update_item.return_value = {
            "Attributes": {"count": {"N": str(count_after_update)}}
        }
    return client


# --- circuit breaker -------------------------------------------------

def test_circuit_breaker_blocks_when_paused():
    client = make_ssm_client(paused="true")
    result = guardrails.check_circuit_breaker(client, "/orchestrator/paused")
    assert result.allowed is False
    assert result.reason == "circuit_breaker_paused"


def test_circuit_breaker_allows_when_not_paused():
    client = make_ssm_client(paused="false")
    result = guardrails.check_circuit_breaker(client, "/orchestrator/paused")
    assert result.allowed is True


def test_circuit_breaker_allows_when_parameter_missing():
    client = make_ssm_client(raise_not_found=True)
    result = guardrails.check_circuit_breaker(client, "/orchestrator/paused")
    assert result.allowed is True


def test_circuit_breaker_reads_with_decryption():
    client = make_ssm_client(paused="false")
    guardrails.check_circuit_breaker(client, "/orchestrator/paused")
    _, kwargs = client.get_parameter.call_args
    assert kwargs["WithDecryption"] is True


def test_trip_circuit_breaker_writes_secure_string():
    client = MagicMock()
    guardrails.trip_circuit_breaker(client, "/orchestrator/paused", "arn:aws:kms:key")
    client.put_parameter.assert_called_once_with(
        Name="/orchestrator/paused",
        Value="true",
        Type="SecureString",
        KeyId="arn:aws:kms:key",
        Overwrite=True,
    )


# --- rate limit --------------------------------------------------------

def test_rate_limit_allows_under_threshold():
    client = make_dynamodb_client(count_after_update=3)
    result = guardrails.check_rate_limit(client, "table", "policy-1", max_per_hour=10)
    assert result.allowed is True
    assert result.reason == "count=3/10"


def test_rate_limit_blocks_over_threshold():
    client = make_dynamodb_client(raise_conditional_failed=True)
    result = guardrails.check_rate_limit(client, "table", "policy-1", max_per_hour=10)
    assert result.allowed is False
    assert result.reason == "rate_limit_exceeded"


def test_rate_limit_buckets_by_hour():
    client = make_dynamodb_client(count_after_update=1)
    guardrails.check_rate_limit(client, "table", "policy-1", max_per_hour=10, now=3600.0)
    _args, kwargs = client.update_item.call_args
    assert kwargs["Key"]["counter_key"]["S"] == "policy-1#1"


# --- resource denylist ---------------------------------------------------

def test_denylist_blocks_tagged_resource():
    client = MagicMock()
    client.get_resources.return_value = {
        "ResourceTagMappingList": [
            {"Tags": [{"Key": "do-not-remediate", "Value": "true"}]}
        ]
    }
    result = guardrails.check_resource_denylist(client, "arn:aws:s3:::bucket")
    assert result.allowed is False
    assert result.reason == "resource_tagged_do_not_remediate"


def test_denylist_allows_untagged_resource():
    client = MagicMock()
    client.get_resources.return_value = {
        "ResourceTagMappingList": [{"Tags": [{"Key": "env", "Value": "prod"}]}]
    }
    result = guardrails.check_resource_denylist(client, "arn:aws:s3:::bucket")
    assert result.allowed is True


def test_denylist_allows_when_no_resource_arn():
    client = MagicMock()
    result = guardrails.check_resource_denylist(client, "")
    assert result.allowed is True
    client.get_resources.assert_not_called()


@pytest.mark.parametrize("tag_value", ["TRUE", "True", "true"])
def test_denylist_tag_match_is_case_insensitive_on_value(tag_value):
    client = MagicMock()
    client.get_resources.return_value = {
        "ResourceTagMappingList": [{"Tags": [{"Key": "do-not-remediate", "Value": tag_value}]}]
    }
    result = guardrails.check_resource_denylist(client, "arn:aws:s3:::bucket")
    assert result.allowed is False
