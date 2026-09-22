"""State machine step 1: parse the incoming EventBridge/Security Hub event.

Input: the raw EventBridge event for an "Security Hub Findings - Imported"
rule (``event["detail"]["findings"]`` is a list; Security Hub batches, we
process the first finding in the batch - see docs/ARCHITECTURE.md for why
the EventBridge rule targets a single-finding Step Functions execution
rather than fanning the batch out itself).

Output: the normalized finding dict (remediation_common.asff.normalize),
or a ``{"skip": True, "skip_reason": ...}`` marker the state machine's
first Choice state routes straight to RecordSkipped.
"""
from __future__ import annotations

from typing import Any

from remediation_common import asff


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    findings = event.get("detail", {}).get("findings", [])
    if not findings:
        return {"skip": True, "skip_reason": "no_findings_in_event"}

    try:
        normalized = asff.normalize(findings[0])
    except asff.MalformedFindingError as exc:
        return {"skip": True, "skip_reason": f"malformed_finding: {exc}"}

    if not asff.should_process(normalized):
        return {
            "skip": True,
            "skip_reason": "not_active_or_already_triaged",
            "finding": normalized,
        }

    return {"skip": False, "finding": normalized}
