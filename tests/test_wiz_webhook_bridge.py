import base64
import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

LAMBDA = "terraform/modules/wiz-finding-bridge/lambda/wiz_webhook_bridge.py"
SECRET = "s3cr3t-token-value"


@pytest.fixture
def make_fn(load_module):
    def _make(**env):
        module = load_module(
            LAMBDA,
            SNS_TOPIC_ARN="arn:aws:sns:us-east-1:123456789012:alerts",
            WEBHOOK_SECRET_ARN="arn:aws:secretsmanager:us-east-1:123456789012:secret:wiz",
            ACCOUNT_ID="123456789012",
            AWS_REGION="us-east-1",
            **env,
        )
        module.secretsmanager = MagicMock()
        module.secretsmanager.get_secret_value.return_value = {"SecretString": SECRET}
        module.sns = MagicMock()
        module.securityhub = MagicMock()
        module.securityhub.batch_import_findings.return_value = {"FailedCount": 0}
        return module

    return _make


@pytest.fixture
def fn(make_fn):
    return make_fn()


def _event(payload, token=SECRET, b64=False):
    body = payload if isinstance(payload, str) else json.dumps(payload)
    if b64:
        body = base64.b64encode(body.encode()).decode()
    return {"pathParameters": {"secretToken": token}, "body": body, "isBase64Encoded": b64}


def test_wrong_token_is_rejected(fn):
    response = fn.lambda_handler(_event({"severity": "CRITICAL"}, token="guess"), None)

    assert response["statusCode"] == 401
    fn.sns.publish.assert_not_called()


def test_non_ascii_token_is_a_clean_401_not_a_crash(fn):
    response = fn.lambda_handler(_event({"severity": "CRITICAL"}, token="é" * 10), None)

    assert response["statusCode"] == 401


def test_unreadable_secret_rejects_every_delivery(fn):
    fn.secretsmanager.get_secret_value.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "GetSecretValue")

    assert fn.lambda_handler(_event({"severity": "CRITICAL"}), None)["statusCode"] == 401


def test_secret_is_cached_between_deliveries(fn):
    fn.lambda_handler(_event({"severity": "HIGH"}), None)
    fn.lambda_handler(_event({"severity": "HIGH"}), None)

    assert fn.secretsmanager.get_secret_value.call_count == 1


def test_high_finding_is_published(fn):
    fn.lambda_handler(_event({"severity": "HIGH", "title": "Public bucket", "primaryResource": {"id": "b1"}}), None)

    kwargs = fn.sns.publish.call_args.kwargs
    assert kwargs["Subject"] == "Wiz finding: Public bucket"
    assert '"id": "b1"' in kwargs["Message"]


def test_finding_below_threshold_is_dropped(fn):
    response = fn.lambda_handler(_event({"severity": "LOW", "title": "Minor"}), None)

    assert "below MIN_SEVERITY" in response["body"]
    fn.sns.publish.assert_not_called()


def test_unresolved_severity_fails_open(fn):
    fn.lambda_handler(_event({"title": "No severity field"}), None)

    assert "unresolved - check SEVERITY_FIELD_PATH" in fn.sns.publish.call_args.kwargs["Message"]


def test_nested_field_paths(make_fn):
    fn = make_fn(SEVERITY_FIELD_PATH="issue.severity", TITLE_FIELD_PATH="issue.rule.name")

    fn.lambda_handler(_event({"issue": {"severity": "critical", "rule": {"name": "Admin role"}}}), None)

    assert fn.sns.publish.call_args.kwargs["Subject"] == "Wiz finding: Admin role"


def test_subject_is_sanitized_for_sns(fn):
    fn.lambda_handler(_event({"severity": "HIGH", "title": "Line one\nLine two – café" * 5}), None)

    subject = fn.sns.publish.call_args.kwargs["Subject"]
    assert all(0x20 <= ord(ch) <= 0x7E for ch in subject)
    assert len(subject) <= 100


def _imported(fn):
    return fn.securityhub.batch_import_findings.call_args.kwargs["Findings"][0]


def test_finding_is_imported_as_asff(make_fn):
    fn = make_fn(RESOURCE_ID_FIELD_PATH="primaryResource.arn")

    fn.lambda_handler(
        _event({
            "id": "issue-1",
            "severity": "HIGH",
            "title": "Open SSH",
            "primaryResource": {"arn": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-1"},
        }),
        None,
    )

    finding = _imported(fn)
    assert finding["Id"] == "wiz/issue-1"
    assert finding["GeneratorId"] == "wiz/Open SSH"
    assert finding["ProductArn"] == "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default"
    assert finding["AwsAccountId"] == "123456789012"
    assert finding["Severity"] == {"Label": "HIGH"}
    assert finding["Resources"] == [{"Type": "Other", "Id": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-1"}]
    assert "Imported into Security Hub as: wiz/issue-1" in fn.sns.publish.call_args.kwargs["Message"]


def test_unresolved_fields_get_placeholders(fn):
    fn.lambda_handler(_event({"title": "No id, no severity"}), None)

    finding = _imported(fn)
    assert finding["Resources"][0]["Id"] == "wiz-unresolved-resource"
    assert finding["Severity"] == {"Label": "INFORMATIONAL"}
    assert len(finding["Id"]) == len("wiz/") + 64


def test_same_payload_gets_the_same_fallback_id(fn):
    fn.lambda_handler(_event({"title": "Repeat"}), None)
    first = _imported(fn)["Id"]
    fn.lambda_handler(_event({"title": "Repeat"}), None)

    assert _imported(fn)["Id"] == first


def test_below_threshold_is_not_imported(fn):
    fn.lambda_handler(_event({"severity": "LOW", "title": "Minor"}), None)

    fn.securityhub.batch_import_findings.assert_not_called()


def test_rejected_import_still_notifies(fn):
    fn.securityhub.batch_import_findings.return_value = {"FailedCount": 1, "FailedFindings": [{"ErrorCode": "x"}]}

    response = fn.lambda_handler(_event({"severity": "HIGH", "title": "Rejected"}), None)

    assert response["statusCode"] == 200
    assert "Security Hub import FAILED" in fn.sns.publish.call_args.kwargs["Message"]


def test_import_error_still_notifies(fn):
    fn.securityhub.batch_import_findings.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "BatchImportFindings")

    fn.lambda_handler(_event({"severity": "HIGH", "title": "Denied"}), None)

    assert "Security Hub import FAILED" in fn.sns.publish.call_args.kwargs["Message"]


def test_base64_body_is_decoded(fn):
    fn.lambda_handler(_event({"severity": "CRITICAL", "title": "Encoded"}, b64=True), None)

    assert fn.sns.publish.call_args.kwargs["Subject"] == "Wiz finding: Encoded"


def test_invalid_json_is_acknowledged_without_retry(fn):
    response = fn.lambda_handler(_event("not json"), None)

    assert response["statusCode"] == 200
    fn.sns.publish.assert_not_called()
