import json
import time
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber
from remediation_common import approvals


@pytest.fixture
def callback(load_module):
    module = load_module(
        "terraform/lambda/approval_callback/handler.py",
        PENDING_APPROVALS_TABLE_NAME="pending",
        SIGNING_SECRET_ARN="secret",
    )
    module._secret_cache["value"] = "secret"
    module._dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
    module._sfn = MagicMock()
    return module


def event(method="POST", decision="approve", authenticated=True):
    context = {"http": {"method": method}}
    if authenticated:
        context["authorizer"] = {"iam": {"userArn": "arn:aws:sts::123456789012:assumed-role/approver/alice"}}
    params = {
        "approval_id": "request-1",
        "decision": decision,
        "sig": approvals.sign("request-1", decision, "secret"),
    }
    return {"requestContext": context, "queryStringParameters": params}


def pending_item(**overrides):
    item = approvals.build_pending_item(
        approval_id="request-1", task_token="token", finding_id="finding-1", policy_id="policy-1"
    )
    return {**item, **overrides}


def get_response(item):
    from boto3.dynamodb.types import TypeSerializer

    return {"Item": {k: TypeSerializer().serialize(v) for k, v in item.items()}}


def test_get_only_reviews_without_consuming_or_delivering(callback):
    with Stubber(callback._dynamodb.meta.client) as stub:
        stub.add_response("get_item", get_response(pending_item()))
        response = callback.handler(event("GET", authenticated=False), None)
        assert response["statusCode"] == 200
        assert "POST" in response["body"]
        stub.assert_no_pending_responses()
    callback._sfn.send_task_success.assert_not_called()
    callback._sfn.send_task_failure.assert_not_called()


def test_post_requires_gateway_authenticated_identity(callback):
    with Stubber(callback._dynamodb.meta.client):
        assert callback.handler(event(authenticated=False), None)["statusCode"] == 403
    callback._sfn.send_task_success.assert_not_called()


def test_unknown_method_is_rejected(callback):
    with Stubber(callback._dynamodb.meta.client):
        assert callback.handler(event("DELETE"), None)["statusCode"] == 405


@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_decision_is_delivered_with_authenticated_actor(callback, decision):
    with Stubber(callback._dynamodb.meta.client) as stub:
        stub.add_response("get_item", get_response(pending_item()))
        stub.add_response("update_item", {})  # reserve immutable decision and actor
        stub.add_response("update_item", {})  # acknowledge delivery
        assert callback.handler(event(decision=decision), None)["statusCode"] == 200
        stub.assert_no_pending_responses()
    payload = json.loads(callback._sfn.send_task_success.call_args.kwargs["output"])
    assert payload == {"decision": decision, "decided_by": event()["requestContext"]["authorizer"]["iam"]["userArn"]}


def test_delivery_failure_can_retry_the_same_reserved_decision(callback):
    actor = event()["requestContext"]["authorizer"]["iam"]["userArn"]
    callback._sfn.send_task_success.side_effect = [
        ClientError({"Error": {"Code": "KmsThrottlingException"}}, "SendTaskSuccess"), None
    ]
    with Stubber(callback._dynamodb.meta.client) as stub:
        stub.add_response("get_item", get_response(pending_item()))
        stub.add_response("update_item", {})
        assert callback.handler(event(), None)["statusCode"] == 503
        stub.add_response("get_item", get_response(pending_item(decision="approve", decided_by=actor)))
        stub.add_response("update_item", {})
        stub.add_response("update_item", {})
        assert callback.handler(event(), None)["statusCode"] == 200
        stub.assert_no_pending_responses()
    assert callback._sfn.send_task_success.call_count == 2


def test_competing_decision_cannot_replace_the_first(callback):
    with Stubber(callback._dynamodb.meta.client) as stub:
        stub.add_response("get_item", get_response(pending_item()))
        stub.add_client_error("update_item", "ConditionalCheckFailedException")
        assert callback.handler(event(decision="deny"), None)["statusCode"] == 409
    callback._sfn.send_task_success.assert_not_called()


def test_expired_request_cannot_be_decided(callback):
    with Stubber(callback._dynamodb.meta.client) as stub:
        stub.add_response("get_item", get_response(pending_item(expires_at=int(time.time()) - 1)))
        assert callback.handler(event(), None)["statusCode"] == 410
    callback._sfn.send_task_success.assert_not_called()


def test_closed_token_does_not_claim_delivery_succeeded(callback):
    callback._sfn.send_task_success.side_effect = ClientError(
        {"Error": {"Code": "TaskTimedOut"}}, "SendTaskSuccess"
    )
    with Stubber(callback._dynamodb.meta.client) as stub:
        stub.add_response("get_item", get_response(pending_item()))
        stub.add_response("update_item", {})
        response = callback.handler(event(), None)
        assert response["statusCode"] == 410
        assert "history" in response["body"]
