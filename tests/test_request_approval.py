from unittest.mock import MagicMock

HANDLER = "terraform/lambda/request_approval/handler.py"
ENV = {
    "PENDING_APPROVALS_TABLE_NAME": "pending",
    "NOTIFICATION_TOPIC_ARN": "arn:aws:sns:us-east-1:111111111111:topic",
    "APPROVAL_BASE_URL": "https://abc.execute-api.us-east-1.amazonaws.com/decision",
    "SIGNING_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:111111111111:secret:s",
}
FINDING = {
    "finding_id": "f-1",
    "title": "Credential exfiltration",
    "resource_arn": "arn:aws:iam::111111111111:user/alice",
    "resource_type": "AwsIamAccessKey",
    "account_id": "111111111111",
    "region": "us-east-1",
    "product_arn": "arn:aws:securityhub:us-east-1:111111111111:product/111111111111/default",
    "generator_id": "custom-importer",
}
POLICY = {"match_id": "guardduty-creds", "action_document": "DisableCompromisedCredentials"}


def _handler(load_module):
    module = load_module(HANDLER, **ENV)
    module._dynamodb = MagicMock()
    module._sns = MagicMock()
    module._secretsmanager = MagicMock()
    module._secretsmanager.get_secret_value.return_value = {"SecretString": "secret"}
    return module


def test_approval_message_names_the_finding_source(load_module):
    module = _handler(load_module)

    module.handler({"finding": FINDING, "policy": POLICY, "task_token": "tok"}, None)

    message = module._sns.publish.call_args.kwargs["Message"]
    # A self-imported finding must be visible as such to the approver.
    assert f"Source: {FINDING['product_arn']}" in message
    assert "Generator: custom-importer" in message
    stored = module._dynamodb.Table.return_value.put_item.call_args.kwargs["Item"]
    assert stored["task_token"] == "tok"
    assert "tok" not in message


def test_approval_message_tolerates_a_finding_without_a_source(load_module):
    module = _handler(load_module)
    finding = {k: v for k, v in FINDING.items() if k not in ("product_arn", "generator_id")}

    module.handler({"finding": finding, "policy": POLICY, "task_token": "tok"}, None)

    assert "Source: unknown" in module._sns.publish.call_args.kwargs["Message"]


def test_approval_message_states_the_configured_timeout(load_module, monkeypatch):
    monkeypatch.setenv("APPROVAL_TIMEOUT_SECONDS", "600")
    module = _handler(load_module)

    module.handler({"finding": FINDING, "policy": POLICY, "task_token": "tok"}, None)

    message = module._sns.publish.call_args.kwargs["Message"]
    assert "expires in 10 minutes" in message
    assert "24 hours" not in message


def test_default_timeout_reads_as_24_hours(load_module):
    module = _handler(load_module)

    assert module._duration(86400) == "24 hours"
    assert module._duration(3600) == "1 hour"
    assert module._duration(90) == "1 minute"
    assert module._duration(5400) == "90 minutes"
