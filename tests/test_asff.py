import pytest
from remediation_common import asff

BASE_FINDING = {
    "Id": "finding-1",
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
    "Title": "S3 bucket is publicly accessible",
    "Types": ["Software and Configuration Checks/S3/PublicAccess"],
    "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/S3.8",
    "Severity": {"Label": "HIGH"},
    "Workflow": {"Status": "NEW"},
    "RecordState": "ACTIVE",
    "AwsAccountId": "123456789012",
    "Region": "us-east-1",
    "Resources": [
        {
            "Id": "arn:aws:s3:::my-bucket",
            "Type": "AwsS3Bucket",
            "Tags": {"do-not-remediate": "true"},
        }
    ],
    "FirstObservedAt": "2026-09-20T00:00:00Z",
    "Description": "A bucket allows public access.",
}


def test_normalize_extracts_expected_fields():
    normalized = asff.normalize(BASE_FINDING)

    assert normalized["finding_id"] == "finding-1"
    assert normalized["type_prefix"] == "Software and Configuration Checks/S3/PublicAccess"
    assert normalized["severity_label"] == "HIGH"
    assert normalized["account_id"] == "123456789012"
    assert normalized["resource_arn"] == "arn:aws:s3:::my-bucket"
    assert normalized["resource_type"] == "AwsS3Bucket"
    assert normalized["resource_tags"] == {"do-not-remediate": "true"}


def test_normalize_falls_back_to_region_from_product_arn():
    finding = {**BASE_FINDING}
    del finding["Region"]
    normalized = asff.normalize(finding)
    assert normalized["region"] == "us-east-1"


def test_normalize_handles_no_resources():
    finding = {**BASE_FINDING, "Resources": []}
    normalized = asff.normalize(finding)
    assert normalized["resource_arn"] == ""
    assert normalized["resource_type"] == "Other"


def test_normalize_raises_on_missing_required_field():
    finding = {k: v for k, v in BASE_FINDING.items() if k != "AwsAccountId"}
    with pytest.raises(asff.MalformedFindingError):
        asff.normalize(finding)


@pytest.mark.parametrize(
    ("record_state", "workflow_status", "expected"),
    [
        ("ACTIVE", "NEW", True),
        ("ACTIVE", "NOTIFIED", True),
        ("ACTIVE", "RESOLVED", False),
        ("ACTIVE", "SUPPRESSED", False),
        ("ARCHIVED", "NEW", False),
    ],
)
def test_should_process(record_state, workflow_status, expected):
    normalized = {"record_state": record_state, "workflow_status": workflow_status}
    assert asff.should_process(normalized) is expected


@pytest.mark.parametrize(
    ("label", "threshold", "expected"),
    [
        ("HIGH", "MEDIUM", True),
        ("LOW", "MEDIUM", False),
        ("CRITICAL", None, True),
        ("INFORMATIONAL", "LOW", False),
        ("SOMETHING_UNKNOWN", "HIGH", True),  # fails open, see docstring
    ],
)
def test_meets_severity_threshold(label, threshold, expected):
    assert asff.meets_severity_threshold(label, threshold) is expected
