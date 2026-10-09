"""Normalize every finding for the bounded Map state, retaining rejected inputs."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from remediation_common import asff


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    detail = event.get("detail")
    findings = detail.get("findings") if isinstance(detail, dict) else None
    if not isinstance(findings, list) or not findings:
        findings = [None]
    event_id = event.get("id") or hashlib.sha256(
        json.dumps(event, sort_keys=True).encode()
    ).hexdigest()
    results = []
    for index, finding in enumerate(findings):
        try:
            normalized = asff.normalize(finding)
            skip = not asff.should_process(normalized)
            reason = "not_active_or_already_triaged" if skip else None
        except (asff.MalformedFindingError, TypeError, AttributeError, IndexError):
            # Do not retain attacker-controlled payloads or exception details.
            normalized = {
                "finding_id": f"rejected:{event_id}:{index}", "title": "Rejected finding input",
                "account_id": str(event.get("account") or "unknown"),
                "region": str(event.get("region") or "unknown"), "resource_arn": "",
                "resource_type": "Other", "generator_id": "input-validation", "severity_label": "INFORMATIONAL",
            }
            skip, reason = True, "malformed_finding_or_empty_batch"
        results.append({
            "skip": skip, "finding": normalized,
            "guardrail_result": {"allowed": False if skip else None, "reason": reason},
        })
    return {"findings": results}
