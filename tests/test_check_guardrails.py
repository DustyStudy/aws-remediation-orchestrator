from unittest.mock import MagicMock

import pytest

HANDLER = "terraform/lambda/check_guardrails/handler.py"
HUB_ARN = "arn:aws:lambda:us-east-1:111111111111:function:remediation-orchestrator-check-guardrails"
ENV = {
    "PAUSE_PARAMETER_NAME": "/remediation-orchestrator/paused",
    "PAUSE_PARAMETER_KMS_KEY_ID": "key",
    "RATE_LIMIT_TABLE_NAME": "rate-limit",
    "MEMBER_GUARDRAILS_ROLE_NAME": "remediation-orchestrator-member-guardrails-role",
    "MEMBER_ACCOUNT_IDS": "222222222222",
}
POLICY = {"match_id": "s3-public-access", "max_actions_per_hour": 20}


class Context:
    invoked_function_arn = HUB_ARN


def finding(account_id):
    return {"account_id": account_id, "resource_arn": "arn:aws:s3:::bucket"}


@pytest.fixture
def handler(load_module):
    module = load_module(HANDLER, **ENV)
    module._ssm = MagicMock()
    module._ssm.get_parameter.return_value = {"Parameter": {"Value": "false"}}
    module._dynamodb = MagicMock()
    module._dynamodb.update_item.return_value = {"Attributes": {"count": {"N": "1"}}}
    module._tagging = MagicMock()
    module._tagging.get_resources.return_value = {"ResourceTagMappingList": []}
    module._sts = MagicMock()
    module._sts.assume_role.return_value = {
        "Credentials": {"AccessKeyId": "ASIA", "SecretAccessKey": "s", "SessionToken": "t"}
    }
    return module


def test_member_account_denylist_tag_is_read_in_the_member_account(handler, monkeypatch):
    member_tagging = MagicMock()
    member_tagging.get_resources.return_value = {
        "ResourceTagMappingList": [{"Tags": [{"Key": "do-not-remediate", "Value": "true"}]}]
    }
    monkeypatch.setattr(handler.boto3, "client", MagicMock(return_value=member_tagging))

    result = handler.handler({"finding": finding("222222222222"), "policy": POLICY}, Context())

    assert handler._sts.assume_role.call_args.kwargs["RoleArn"] == (
        "arn:aws:iam::222222222222:role/remediation-orchestrator-member-guardrails-role"
    )
    handler._tagging.get_resources.assert_not_called()
    assert result["guardrail_result"]["allowed"] is False
    assert result["guardrail_result"]["reason"] == "resource_tagged_do_not_remediate"


def test_hub_account_finding_uses_the_local_tagging_client(handler):
    result = handler.handler({"finding": finding("111111111111"), "policy": POLICY}, Context())

    handler._sts.assume_role.assert_not_called()
    handler._tagging.get_resources.assert_called_once()
    assert result["guardrail_result"]["allowed"] is True


def test_account_that_is_not_onboarded_is_blocked_without_spending_rate_limit(handler):
    result = handler.handler({"finding": finding("333333333333"), "policy": POLICY}, Context())

    assert result["guardrail_result"] == {"allowed": False, "reason": "account_not_onboarded"}
    handler._dynamodb.update_item.assert_not_called()
    handler._sts.assume_role.assert_not_called()


def test_blocked_attempts_trip_the_breaker_at_the_multiplier(handler):
    class ConditionalCheckFailedException(Exception):
        pass

    handler._dynamodb.exceptions.ConditionalCheckFailedException = ConditionalCheckFailedException
    # First call is the real check and is over the limit. The second is the
    # breaker's own count, which reports 3x the policy's 20 per hour.
    handler._dynamodb.update_item.side_effect = [
        ConditionalCheckFailedException(),
        {"Attributes": {"count": {"N": "60"}}},
    ]

    result = handler.handler({"finding": finding("111111111111"), "policy": POLICY}, Context())

    assert result["guardrail_result"]["allowed"] is False
    handler._ssm.put_parameter.assert_called_once()
