import pytest


def finding(identifier):
    return {
        "Id": identifier, "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/test",
        "Title": "Example", "GeneratorId": "test", "AwsAccountId": "123456789012",
    }


def test_every_finding_in_a_batch_is_normalized(load_module):
    module = load_module("terraform/lambda/normalize_finding/handler.py")
    result = module.handler({"detail": {"findings": [finding("one"), finding("two")]}}, None)
    assert [item["finding"]["finding_id"] for item in result["findings"]] == ["one", "two"]
    assert all(not item["skip"] for item in result["findings"])


@pytest.mark.parametrize("bad", [
    {}, None, "invalid", {**finding("bad"), "Severity": "HIGH"},
    {**finding("bad"), "Resources": {"bad": {}}},
    {**finding("bad"), "Types": {"bad": "x"}},
    {**finding("bad"), "Id": None}, {**finding("bad"), "Id": ""},
])
def test_malformed_finding_is_recordable_without_losing_its_neighbor(load_module, bad):
    module = load_module("terraform/lambda/normalize_finding/handler.py")
    result = module.handler({"id": "event-1", "detail": {"findings": [bad, finding("valid")]}}, None)
    rejected, valid = result["findings"]
    assert rejected["skip"]
    assert rejected["finding"]["finding_id"]
    assert rejected["guardrail_result"]["reason"].startswith("malformed_finding")
    assert valid["finding"]["finding_id"] == "valid"


@pytest.mark.parametrize("payload", [{}, {"detail": {"findings": []}}, {"detail": None}, {"detail": {"findings": "invalid"}}])
def test_empty_or_malformed_envelope_has_an_auditable_outcome(load_module, payload):
    module = load_module("terraform/lambda/normalize_finding/handler.py")
    result = module.handler(payload, None)
    assert len(result["findings"]) == 1
    assert result["findings"][0]["skip"]
    assert result["findings"][0]["finding"]["finding_id"].startswith("rejected:")
