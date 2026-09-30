from unittest.mock import MagicMock

import pytest

SCRIPT = "terraform/ssm-documents/scripts/disable_access_keys.py"


@pytest.fixture
def script(load_module, monkeypatch):
    module = load_module(SCRIPT)
    iam = MagicMock()
    iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {"AccessKeyId": "AKIA1", "Status": "Active"},
            {"AccessKeyId": "AKIA2", "Status": "Inactive"},
        ]
    }
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012"}
    clients = {"iam": iam, "sts": sts}
    monkeypatch.setattr(module.boto3, "client", lambda service: clients[service])
    module.iam = iam
    return module


def _run(script, **overrides):
    # Security Hub's copy of a GuardDuty IAM finding: the first resource is
    # the access key (or an instance), never the user.
    events = {
        "ResourceArn": "AWS::IAM::AccessKey:AKIA1",
        "FindingId": "f-1",
        "AccountId": "123456789012",
        "UserName": "alice",
        **overrides,
    }
    return script.handler(events, None)


def test_deactivates_only_active_keys_of_the_named_user(script):
    result = _run(script)

    script.iam.list_access_keys.assert_called_once_with(UserName="alice")
    script.iam.update_access_key.assert_called_once_with(
        UserName="alice", AccessKeyId="AKIA1", Status="Inactive"
    )
    assert result == {"UserName": "alice", "DisabledAccessKeyIds": ["AKIA1"]}


def test_falls_back_to_an_iam_user_arn(script):
    result = _run(script, UserName="unspecified", ResourceArn="arn:aws:iam::123456789012:user/team/bob")

    assert result["UserName"] == "bob"


@pytest.mark.parametrize(
    "resource_arn",
    ["AWS::IAM::AccessKey:AKIA1", "arn:aws:ec2:us-east-1:123456789012:instance/i-1"],
)
def test_refuses_when_the_finding_names_no_user(script, resource_arn):
    with pytest.raises(ValueError, match="names no IAM user"):
        _run(script, UserName="unspecified", ResourceArn=resource_arn)

    script.iam.update_access_key.assert_not_called()


def test_refuses_a_user_in_another_account(script):
    with pytest.raises(ValueError, match="account 210987654321"):
        _run(script, AccountId="210987654321")

    script.iam.update_access_key.assert_not_called()
