"""Signing/verification for the human-approval callback links.

The approval SNS message includes one-click approve/deny links. Rather than
putting the raw Step Functions task token in the URL (long, and a bearer
credential on its own), we store the token in DynamoDB under a short random
``approval_id`` and put only that id plus an HMAC signature in the link.
The signature stops anyone from guessing or tampering with an approval_id;
it is not a substitute for a real identity check on who clicked - see the
"Known limitations" note in docs/ARCHITECTURE.md.
"""
from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from typing import Any

APPROVAL_TTL_SECONDS = 24 * 3600


def new_approval_id() -> str:
    return uuid.uuid4().hex


def sign(approval_id: str, decision: str, secret: str) -> str:
    message = f"{approval_id}:{decision}".encode()
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def verify(approval_id: str, decision: str, signature: str, secret: str) -> bool:
    expected = sign(approval_id, decision, secret)
    return hmac.compare_digest(expected, signature)


def build_pending_item(
    *, approval_id: str, task_token: str, finding_id: str, policy_id: str, now: float | None = None
) -> dict[str, Any]:
    now = time.time() if now is None else now
    return {
        "approval_id": approval_id,
        "task_token": task_token,
        "finding_id": finding_id,
        "policy_id": policy_id,
        "created_at": int(now),
        "expires_at": int(now) + APPROVAL_TTL_SECONDS,
        "consumed": False,
    }
