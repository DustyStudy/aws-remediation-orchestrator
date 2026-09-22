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
