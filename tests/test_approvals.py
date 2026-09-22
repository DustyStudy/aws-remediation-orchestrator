from remediation_common import approvals


def test_sign_and_verify_roundtrip():
    signature = approvals.sign("abc123", "approve", "secret")
    assert approvals.verify("abc123", "approve", signature, "secret") is True


def test_verify_rejects_wrong_secret():
    signature = approvals.sign("abc123", "approve", "secret")
    assert approvals.verify("abc123", "approve", signature, "wrong-secret") is False


def test_verify_rejects_tampered_decision():
    # Signature computed for "approve" must not validate a "deny" decision -
    # this is exactly the tampering approval_callback.handler guards against.
    signature = approvals.sign("abc123", "approve", "secret")
    assert approvals.verify("abc123", "deny", signature, "secret") is False


def test_verify_rejects_tampered_approval_id():
    signature = approvals.sign("abc123", "approve", "secret")
    assert approvals.verify("xyz789", "approve", signature, "secret") is False


def test_new_approval_id_is_unique():
    ids = {approvals.new_approval_id() for _ in range(100)}
    assert len(ids) == 100


def test_build_pending_item_sets_ttl_and_unconsumed():
    item = approvals.build_pending_item(
        approval_id="abc123",
        task_token="token-xyz",
        finding_id="finding-1",
        policy_id="policy-1",
        now=1000.0,
    )
    assert item["approval_id"] == "abc123"
    assert item["consumed"] is False
    assert item["expires_at"] == 1000 + approvals.APPROVAL_TTL_SECONDS
