from remediation_common import ledger

FINDING = {
    "finding_id": "finding-1",
    "account_id": "123456789012",
    "region": "us-east-1",
    "resource_arn": "arn:aws:s3:::my-bucket",
    "resource_type": "AwsS3Bucket",
    "generator_id": "aws-foundational-security-best-practices/v/1.0.0/S3.8",
    "title": "S3 bucket is publicly accessible",
    "severity_label": "HIGH",
}

POLICY = {
    "match_id": "s3-public-access",
    "mode": "auto",
    "action_document": "S3PublicAccessRemediation",
    "nist_controls": ["AC-3", "SC-28"],
}


def test_build_ledger_item_shape():
    item = ledger.build_ledger_item(
        finding=FINDING,
        policy=POLICY,
        guardrail_result={"allowed": True, "reason": None},
        outcome="executed",
        decided_by="system",
        execution_id="exec-123",
        execution_status="Success",
        timestamp="2026-09-22T00:00:00+00:00",
    )
    assert item["finding_id"] == "finding-1"
    assert item["policy_id"] == "s3-public-access"
    assert item["outcome"] == "executed"
    assert item["nist_controls"] == ["AC-3", "SC-28"]
    assert item["execution_id"] == "exec-123"


def test_build_ledger_item_handles_missing_execution_fields():
    item = ledger.build_ledger_item(
        finding=FINDING,
        policy=POLICY,
        guardrail_result={"allowed": False, "reason": "circuit_breaker_paused"},
        outcome="blocked",
        decided_by="system",
        execution_id=None,
        execution_status=None,
        timestamp="2026-09-22T00:00:00+00:00",
    )
    assert item["execution_id"] == ""
    assert item["execution_status"] == ""


def _item(outcome, **overrides):
    base = ledger.build_ledger_item(
        finding=FINDING,
        policy=POLICY,
        guardrail_result={"allowed": True, "reason": None},
        outcome=outcome,
        decided_by="system",
        execution_id="exec-1",
        execution_status="Success",
        timestamp="2026-09-22T00:00:00+00:00",
    )
    base.update(overrides)
    return base


def test_build_evidence_document_counts_outcomes():
    items = [_item("executed"), _item("executed"), _item("dry_run"), _item("blocked"), _item("failed")]
    document = ledger.build_evidence_document(
        account_id="123456789012",
        region="us-east-1",
        ledger_items=items,
        period_start="2026-09-21T00:00:00+00:00",
        period_end="2026-09-22T00:00:00+00:00",
    )
    assert document["data"]["remediated"] == 2
    assert document["data"]["dry_run"] == 1
    assert document["data"]["blocked_by_guardrail"] == 1
    assert document["data"]["failed"] == 1
    assert document["status"] == "fail"  # any failure -> fail
    assert document["schema_version"] == "1.0"
    assert document["collector"] == "aws.remediation_orchestrator"


def test_build_evidence_document_status_pass_with_no_failures():
    items = [_item("executed")]
    document = ledger.build_evidence_document(
        account_id="123456789012",
        region="us-east-1",
        ledger_items=items,
        period_start="2026-09-21T00:00:00+00:00",
        period_end="2026-09-22T00:00:00+00:00",
    )
    assert document["status"] == "pass"


def test_build_evidence_document_status_info_when_empty():
    document = ledger.build_evidence_document(
        account_id="123456789012",
        region="us-east-1",
        ledger_items=[],
        period_start="2026-09-21T00:00:00+00:00",
        period_end="2026-09-22T00:00:00+00:00",
    )
    assert document["status"] == "info"


def test_build_evidence_document_sha256_is_deterministic_and_covers_content():
    items = [_item("executed")]
    doc1 = ledger.build_evidence_document(
        account_id="123456789012",
        region="us-east-1",
        ledger_items=items,
        period_start="2026-09-21T00:00:00+00:00",
        period_end="2026-09-22T00:00:00+00:00",
    )
    doc2 = ledger.build_evidence_document(
        account_id="123456789012",
        region="us-east-1",
        ledger_items=items,
        period_start="2026-09-21T00:00:00+00:00",
        period_end="2026-09-22T00:00:00+00:00",
    )
    assert doc1["sha256"] == doc2["sha256"]

    # sanity: a document with different content hashes differently
    doc3 = ledger.build_evidence_document(
        account_id="123456789012",
        region="us-east-1",
        ledger_items=[_item("executed"), _item("failed")],
        period_start="2026-09-21T00:00:00+00:00",
        period_end="2026-09-22T00:00:00+00:00",
    )
    assert doc3["sha256"] != doc1["sha256"]


def test_build_evidence_document_controls_deduplicated_and_sorted():
    items = [
        _item("executed"),
        _item("executed", nist_controls=["SC-28", "AC-3"]),
    ]
    document = ledger.build_evidence_document(
        account_id="123456789012",
        region="us-east-1",
        ledger_items=items,
        period_start="2026-09-21T00:00:00+00:00",
        period_end="2026-09-22T00:00:00+00:00",
    )
    assert document["controls"]["nist_800_53"] == ["AC-3", "SC-28"]
