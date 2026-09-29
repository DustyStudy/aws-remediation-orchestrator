from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

SCRIPT = "terraform/ssm-documents/scripts/deactivate_stale_access_keys.py"
USER_ARN = "arn:aws:iam::123456789012:user/team/alice"
NOW = datetime.now(timezone.utc)


def _days_ago(days):
    return NOW - timedelta(days=days)


def _key(key_id, age_days, status="Active"):
    return {"AccessKeyId": key_id, "CreateDate": _days_ago(age_days), "Status": status}


@pytest.fixture
def run(load_module, monkeypatch):
    def _run(keys, last_used, tags=(), exempt_tag_key=""):
        module = load_module(SCRIPT)
        iam = MagicMock()
        iam.list_access_keys.return_value = {"AccessKeyMetadata": keys}
        iam.get_access_key_last_used.side_effect = lambda AccessKeyId: {
            "AccessKeyLastUsed": {"LastUsedDate": last_used[AccessKeyId]} if last_used.get(AccessKeyId) else {}
        }
        iam.list_user_tags.return_value = {"Tags": list(tags)}
        monkeypatch.setattr(module.boto3, "client", lambda service: iam)
        result = module.handler(
            {"ResourceArn": USER_ARN, "MaxKeyAgeDays": "90", "MaxUnusedDays": "45", "ExemptTagKey": exempt_tag_key},
            None,
        )
        return result, iam

    return _run


def test_old_key_is_deactivated_even_if_used(run):
    result, iam = run([_key("AKIA1", 120)], {"AKIA1": _days_ago(1)})

    iam.update_access_key.assert_called_once_with(UserName="alice", AccessKeyId="AKIA1", Status="Inactive")
    assert result["DeactivatedAccessKeyIds"] == ["AKIA1"]


def test_unused_key_is_deactivated(run):
    result, _ = run([_key("AKIA1", 60)], {"AKIA1": _days_ago(50)})

    assert result["DeactivatedAccessKeyIds"] == ["AKIA1"]
    assert "unused for 50d" in result["Reasons"]


def test_never_used_key_counts_its_age_as_unused(run):
    result, _ = run([_key("AKIA1", 60)], {})

    assert "never used" in result["Reasons"]


def test_fresh_key_stays_active(run):
    result, iam = run([_key("AKIA1", 30)], {"AKIA1": _days_ago(2)})

    iam.update_access_key.assert_not_called()
    assert result["Reasons"] == "no stale keys"


def test_only_the_stale_key_of_two_is_deactivated(run):
    result, _ = run([_key("OLD", 200), _key("NEW", 10)], {"OLD": _days_ago(1), "NEW": _days_ago(1)})

    assert result["DeactivatedAccessKeyIds"] == ["OLD"]


def test_inactive_key_is_skipped(run):
    _, iam = run([_key("AKIA1", 400, status="Inactive")], {})

    iam.get_access_key_last_used.assert_not_called()
    iam.update_access_key.assert_not_called()


def test_exempt_user_is_skipped(run):
    result, iam = run([_key("AKIA1", 400)], {}, tags=[{"Key": "break-glass", "Value": "yes"}], exempt_tag_key="break-glass")

    iam.list_access_keys.assert_not_called()
    assert result["Reasons"] == "user is exempt"


def test_unreadable_tags_fail_instead_of_guessing(load_module, monkeypatch):
    module = load_module(SCRIPT)
    iam = MagicMock()
    iam.list_user_tags.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "ListUserTags")
    monkeypatch.setattr(module.boto3, "client", lambda service: iam)

    with pytest.raises(ClientError):
        module.handler(
            {"ResourceArn": USER_ARN, "MaxKeyAgeDays": "90", "MaxUnusedDays": "45", "ExemptTagKey": "break-glass"},
            None,
        )
    iam.update_access_key.assert_not_called()
