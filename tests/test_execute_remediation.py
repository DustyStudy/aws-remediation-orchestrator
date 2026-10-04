from unittest.mock import MagicMock

import pytest

HANDLER = "terraform/lambda/execute_remediation/handler.py"
FINDING = {
    "resource_arn": "AWS::IAM::AccessKey:ASIAEXAMPLE",
    "finding_id": "f-1",
    "account_id": "123456789012",
    "principal_role_name": "app-role",
    "principal_user_name": "alice",
}


@pytest.fixture
def handler(load_module):
    return load_module(HANDLER)


def test_revoke_role_sessions_gets_role_and_account(handler):
    params = handler._document_parameters(FINDING, "remediation-orchestrator-RevokeRoleSessions")

    assert params == {
        "ResourceArn": ["AWS::IAM::AccessKey:ASIAEXAMPLE"],
        "FindingId": ["f-1"],
        "AccountId": ["123456789012"],
        "RoleName": ["app-role"],
    }


def test_revoke_role_sessions_without_a_role_passes_the_sentinel(handler):
    finding = {**FINDING, "principal_role_name": ""}

    params = handler._document_parameters(finding, "remediation-orchestrator-RevokeRoleSessions")

    assert params["RoleName"] == ["unspecified"]


def test_disable_compromised_credentials_gets_user_and_account(handler):
    params = handler._document_parameters(FINDING, "remediation-orchestrator-DisableCompromisedCredentials")

    assert params["AccountId"] == ["123456789012"]
    assert params["UserName"] == ["alice"]


def test_other_documents_get_only_the_base_parameters(handler):
    params = handler._document_parameters(FINDING, "remediation-orchestrator-RevokeOpenSshRdpIngress")

    assert set(params) == {"ResourceArn", "FindingId"}


# --- org mode -----------------------------------------------------------

HUB_ARN = "arn:aws:lambda:us-east-1:111111111111:function:remediation-orchestrator-execute-remediation"
MEMBER_ROLE = "remediation-orchestrator-member-execution-role"
MEMBER_FINDING = {**FINDING, "account_id": "222222222222", "resource_arn": "arn:aws:s3:::bucket"}
POLICY = {"action_document": "remediation-orchestrator-S3PublicAccessRemediation"}


class Context:
    invoked_function_arn = HUB_ARN


def make_ssm(status="Success"):
    ssm = MagicMock()
    ssm.start_automation_execution.return_value = {"AutomationExecutionId": "exec-1"}
    ssm.get_automation_execution.return_value = {"AutomationExecution": {"AutomationExecutionStatus": status}}
    return ssm


def test_member_finding_runs_the_shared_document_in_the_member_account(load_module, monkeypatch):
    handler = load_module(HANDLER, MEMBER_EXECUTION_ROLE_NAME=MEMBER_ROLE)
    handler._ssm = make_ssm()
    handler._ssm.describe_document.return_value = {
        "Document": {
            "Parameters": [
                {"Name": "ResourceArn"},
                {
                    "Name": "AutomationAssumeRole",
                    "DefaultValue": "arn:aws:iam::111111111111:role/remediation-orchestrator-s3-automation-role",
                },
            ]
        }
    }
    handler._sts = MagicMock()
    handler._sts.assume_role.return_value = {
        "Credentials": {"AccessKeyId": "ASIA", "SecretAccessKey": "s", "SessionToken": "t"}
    }
    member_ssm = make_ssm()
    monkeypatch.setattr(handler.boto3, "client", MagicMock(return_value=member_ssm))

    result = handler.handler({"finding": MEMBER_FINDING, "policy": POLICY}, Context())

    assert handler._sts.assume_role.call_args.kwargs["RoleArn"] == f"arn:aws:iam::222222222222:role/{MEMBER_ROLE}"
    handler._ssm.start_automation_execution.assert_not_called()
    started = member_ssm.start_automation_execution.call_args.kwargs
    assert started["DocumentName"] == (
        "arn:aws:ssm:us-east-1:111111111111:document/remediation-orchestrator-S3PublicAccessRemediation"
    )
    assert started["Parameters"]["AutomationAssumeRole"] == [
        "arn:aws:iam::222222222222:role/remediation-orchestrator-s3-automation-role"
    ]
    assert started["Parameters"]["ResourceArn"] == ["arn:aws:s3:::bucket"]
    assert result["outcome"] == "executed"


def test_hub_account_finding_runs_locally_in_org_mode(load_module):
    handler = load_module(HANDLER, MEMBER_EXECUTION_ROLE_NAME=MEMBER_ROLE)
    handler._ssm = make_ssm()
    handler._sts = MagicMock()

    handler.handler({"finding": {**MEMBER_FINDING, "account_id": "111111111111"}, "policy": POLICY}, Context())

    handler._sts.assume_role.assert_not_called()
    started = handler._ssm.start_automation_execution.call_args.kwargs
    assert started["DocumentName"] == "remediation-orchestrator-S3PublicAccessRemediation"
    assert "AutomationAssumeRole" not in started["Parameters"]


def test_other_account_finding_stays_local_outside_org_mode(load_module):
    handler = load_module(HANDLER, MEMBER_EXECUTION_ROLE_NAME="")
    handler._ssm = make_ssm(status="Failed")
    handler._sts = MagicMock()

    result = handler.handler({"finding": MEMBER_FINDING, "policy": POLICY}, Context())

    handler._sts.assume_role.assert_not_called()
    assert result["outcome"] == "failed"
