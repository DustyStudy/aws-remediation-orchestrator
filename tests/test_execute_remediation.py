import pytest

HANDLER = "terraform/lambda/execute_remediation/handler.py"
FINDING = {
    "resource_arn": "AWS::IAM::AccessKey:ASIAEXAMPLE",
    "finding_id": "f-1",
    "account_id": "123456789012",
    "principal_role_name": "app-role",
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


def test_other_documents_get_only_the_base_parameters(handler):
    params = handler._document_parameters(FINDING, "remediation-orchestrator-RevokeOpenSshRdpIngress")

    assert set(params) == {"ResourceArn", "FindingId"}
