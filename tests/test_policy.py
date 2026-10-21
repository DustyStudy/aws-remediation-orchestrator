import pytest
from remediation_common import policy

DEFAULT_ITEM = {
    "match_id": "default",
    "match_field": "type_prefix",
    "match_value": "",
    "mode": "dry_run",
    "description": "fallback",
}

S3_ITEM = {
    "match_id": "s3-public-access",
    "match_field": "type_prefix",
    "match_value": "Software and Configuration Checks/S3",
    "mode": "auto",
    "action_document": "S3PublicAccessRemediation",
    "description": "s3",
}

S3_SPECIFIC_ITEM = {
    "match_id": "s3-public-access-critical",
    "match_field": "type_prefix",
    "match_value": "Software and Configuration Checks/S3/PublicAccess",
    "mode": "approval_required",
    "action_document": "S3PublicAccessRemediation",
    "description": "s3, more specific",
}

REGISTRY = [DEFAULT_ITEM, S3_ITEM, S3_SPECIFIC_ITEM]


def test_select_policy_picks_most_specific_match():
    finding = {"type_prefix": "Software and Configuration Checks/S3/PublicAccess/Bucket1"}
    selected = policy.select_policy(REGISTRY, finding)
    assert selected["match_id"] == "s3-public-access-critical"


def test_select_policy_picks_broader_match_when_only_it_fits():
    finding = {"type_prefix": "Software and Configuration Checks/S3/Encryption"}
    selected = policy.select_policy(REGISTRY, finding)
    assert selected["match_id"] == "s3-public-access"


def test_select_policy_falls_back_to_default():
    finding = {"type_prefix": "Unrelated/Finding/Type"}
    selected = policy.select_policy(REGISTRY, finding)
    assert selected["match_id"] == "default"


def test_select_policy_raises_without_default_item():
    with pytest.raises(policy.InvalidPolicyError):
        policy.select_policy([S3_ITEM], {"type_prefix": "nothing matches"})


@pytest.mark.parametrize(
    "item",
    [
        {"match_id": "x", "mode": "not_a_real_mode"},
        {"match_id": "x", "mode": "auto"},  # missing action_document
        {"match_id": "x", "mode": "approval_required"},  # missing action_document
    ],
)
def test_validate_policy_rejects_invalid_items(item):
    with pytest.raises(policy.InvalidPolicyError):
        policy.validate_policy(item)


@pytest.mark.parametrize(
    "item",
    [
        {"match_id": "x", "mode": "ignore"},
        {"match_id": "x", "mode": "dry_run"},
        {"match_id": "x", "mode": "auto", "action_document": "doc"},
        {"match_id": "x", "mode": "approval_required", "action_document": "doc"},
    ],
)
def test_validate_policy_accepts_valid_items(item):
    policy.validate_policy(item)  # should not raise


PHP2SHELL_ITEM = {
    "match_id": "inspector-php2shell-cve-2026-109618",
    "match_field": "vulnerability_id",
    "match_value": "CVE-2026-109618",
    "resource_type": "AwsEc2Instance",
    "mode": "approval_required",
    "action_document": "IsolateCompromisedInstance",
    "description": "php2shell",
}


@pytest.mark.parametrize(
    ("vulnerability_id", "resource_type", "expected"),
    [
        ("CVE-2026-109618", "AwsEc2Instance", "inspector-php2shell-cve-2026-109618"),
        ("CVE-2026-1096180", "AwsEc2Instance", "default"),  # longer id, same prefix
        ("CVE-2026-109618", "AwsEcrContainerImage", "default"),
        ("", "AwsEc2Instance", "default"),
    ],
)
def test_select_policy_matches_vulnerability_id_exactly_and_by_resource_type(
    vulnerability_id, resource_type, expected
):
    finding = {
        "type_prefix": "Software and Configuration Checks/Vulnerabilities/CVE",
        "vulnerability_id": vulnerability_id,
        "resource_type": resource_type,
    }
    selected = policy.select_policy([DEFAULT_ITEM, PHP2SHELL_ITEM], finding)
    assert selected["match_id"] == expected


def test_select_policy_ignores_an_empty_resource_type():
    finding = {"type_prefix": "Software and Configuration Checks/S3/Encryption", "resource_type": "AwsS3Bucket"}
    selected = policy.select_policy([DEFAULT_ITEM, {**S3_ITEM, "resource_type": ""}], finding)
    assert selected["match_id"] == "s3-public-access"


@pytest.mark.parametrize("order", [1, -1])
def test_select_policy_prefers_the_resource_specific_rule_on_a_tie(order):
    any_resource = {**PHP2SHELL_ITEM, "match_id": "php2shell-any", "resource_type": "", "mode": "dry_run"}
    finding = {"vulnerability_id": "CVE-2026-109618", "resource_type": "AwsEc2Instance"}
    registry = [DEFAULT_ITEM, any_resource, PHP2SHELL_ITEM][::order]
    assert policy.select_policy(registry, finding)["match_id"] == "inspector-php2shell-cve-2026-109618"


@pytest.mark.parametrize("order", [1, -1])
def test_select_policy_breaks_a_full_tie_by_the_lower_match_id(order):
    first = {**S3_ITEM, "match_id": "a-s3"}
    second = {**S3_ITEM, "match_id": "b-s3"}
    finding = {"type_prefix": "Software and Configuration Checks/S3/Encryption"}
    registry = [DEFAULT_ITEM, first, second][::order]
    assert policy.select_policy(registry, finding)["match_id"] == "a-s3"
