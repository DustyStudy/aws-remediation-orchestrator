from unittest.mock import MagicMock

from remediation_common import crossaccount

FUNCTION_ARN = "arn:aws-us-gov:lambda:us-gov-west-1:111111111111:function:remediation-orchestrator-x"


def make_sts():
    sts = MagicMock()
    sts.assume_role.return_value = {
        "Credentials": {"AccessKeyId": "ASIA", "SecretAccessKey": "secret", "SessionToken": "token"}
    }
    return sts


def test_member_account_assumes_the_role_in_the_findings_partition_and_account():
    sts = make_sts()

    kwargs = crossaccount.member_client_kwargs(sts, FUNCTION_ARN, "222222222222", "orch-member-execution-role")

    assert sts.assume_role.call_args.kwargs["RoleArn"] == (
        "arn:aws-us-gov:iam::222222222222:role/orch-member-execution-role"
    )
    assert kwargs == {
        "aws_access_key_id": "ASIA",
        "aws_secret_access_key": "secret",
        "aws_session_token": "token",
    }


def test_own_account_stays_local():
    sts = make_sts()

    assert crossaccount.member_client_kwargs(sts, FUNCTION_ARN, "111111111111", "role") is None
    sts.assume_role.assert_not_called()


def test_org_mode_off_stays_local():
    sts = make_sts()

    assert crossaccount.member_client_kwargs(sts, FUNCTION_ARN, "222222222222", "") is None
    sts.assume_role.assert_not_called()


def test_is_onboarded():
    members = ["222222222222"]

    assert crossaccount.is_onboarded(FUNCTION_ARN, "111111111111", members)
    assert crossaccount.is_onboarded(FUNCTION_ARN, "222222222222", members)
    assert not crossaccount.is_onboarded(FUNCTION_ARN, "333333333333", members)
    # Outside org mode nothing is filtered.
    assert crossaccount.is_onboarded(FUNCTION_ARN, "333333333333", [])
