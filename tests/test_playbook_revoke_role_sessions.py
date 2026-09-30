import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

SCRIPT = "terraform/ssm-documents/scripts/revoke_role_sessions.py"
NOW = datetime(2026, 9, 29, 12, 30, 5, tzinfo=timezone.utc)


@pytest.fixture
def script(load_module, monkeypatch):
    module = load_module(SCRIPT)
    iam = MagicMock()
    iam.get_role.return_value = {
        "Role": {"Path": "/", "Arn": "arn:aws:iam::123456789012:role/app-role"}
    }
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012"}
    clients = {"iam": iam, "sts": sts}
    monkeypatch.setattr(module.boto3, "client", lambda service: clients[service])
    monkeypatch.setattr(module, "_now", lambda: NOW)
    module.iam = iam
    return module


def _run(script, **overrides):
    events = {"RoleName": "app-role", "AccountId": "123456789012", "FindingId": "f-1", **overrides}
    return script.handler(events, None)


def test_denies_sessions_issued_before_now(script):
    result = _run(script)

    kwargs = script.iam.put_role_policy.call_args.kwargs
    assert kwargs["RoleName"] == "app-role"
    assert kwargs["PolicyName"] == "AWSRevokeOlderSessions"
    statement = json.loads(kwargs["PolicyDocument"])["Statement"][0]
    assert statement["Effect"] == "Deny"
    assert statement["Action"] == ["*"]
    assert statement["Condition"] == {"DateLessThan": {"aws:TokenIssueTime": "2026-09-29T12:30:05Z"}}
    assert result == {
        "RoleName": "app-role",
        "RoleArn": "arn:aws:iam::123456789012:role/app-role",
        "RevokedBefore": "2026-09-29T12:30:05Z",
    }


def test_role_is_tagged_with_the_finding(script):
    _run(script)

    tags = script.iam.tag_role.call_args.kwargs["Tags"]
    assert {"Key": "RemediationFindingId", "Value": "f-1"} in tags
    assert {"Key": "SessionsRevokedAt", "Value": "2026-09-29T12:30:05Z"} in tags


@pytest.mark.parametrize("role_name", ["", "unspecified"])
def test_missing_role_is_refused(script, role_name):
    with pytest.raises(ValueError, match="no assumed-role principal"):
        _run(script, RoleName=role_name)

    script.iam.put_role_policy.assert_not_called()


def test_role_in_another_account_is_refused(script):
    with pytest.raises(ValueError, match="account 210987654321"):
        _run(script, AccountId="210987654321")

    script.iam.put_role_policy.assert_not_called()


def test_unknown_account_does_not_block(script):
    _run(script, AccountId="unspecified")

    script.iam.put_role_policy.assert_called_once()


def test_identity_center_role_is_refused(script):
    with pytest.raises(ValueError, match="IAM Identity Center"):
        _run(script, RoleName="AWSReservedSSO_AdministratorAccess_0123456789abcdef")

    script.iam.put_role_policy.assert_not_called()


def test_service_linked_role_is_refused(script):
    script.iam.get_role.return_value = {
        "Role": {"Path": "/aws-service-role/ecs.amazonaws.com/", "Arn": "arn:aws:iam::123456789012:role/x"}
    }

    with pytest.raises(ValueError, match="service-linked"):
        _run(script)

    script.iam.put_role_policy.assert_not_called()
