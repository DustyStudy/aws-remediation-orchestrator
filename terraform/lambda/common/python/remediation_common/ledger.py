"""The remediation audit ledger, and its export into GRC evidence format.

Every execution of the state machine - allowed or blocked, auto or
approved, succeeded or failed - writes exactly one ledger item. That item
is the system's audit trail, and ``build_evidence_document`` below is what
turns a batch of them into a document shaped for
`grc-evidence-automation <https://github.com/DustyStudy/grc-evidence-automation>`_
(same field names, same ``schema_version``), so remediation actions taken
here can be ingested as compliance evidence alongside that tool's own
collectors instead of living in a format only this repo understands.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any

EVIDENCE_SCHEMA_VERSION = "1.0"


def build_ledger_item(
    *,
    finding: dict[str, Any],
    policy: dict[str, Any],
    guardrail_result: dict[str, Any],
    outcome: str,
    decided_by: str,
    execution_id: str | None,
    execution_status: str | None,
    timestamp: str,
) -> dict[str, Any]:
    """Assemble one ledger record. ``outcome`` is one of: allowed, blocked,
    dry_run, denied, executed, failed - see docs/POLICY_REGISTRY.md for the
    full state machine of outcomes.
    """
    return {
        "finding_id": finding["finding_id"],
        "execution_ts": timestamp,
        "account_id": finding["account_id"],
        "region": finding["region"],
        "resource_arn": finding["resource_arn"],
        "resource_type": finding["resource_type"],
        "generator_id": finding["generator_id"],
        "title": finding["title"],
        "severity_label": finding["severity_label"],
        "policy_id": policy.get("match_id", "unknown"),
        "mode": policy.get("mode", "unknown"),
        "action_document": policy.get("action_document", ""),
        "nist_controls": policy.get("nist_controls", []),
        "guardrail_allowed": guardrail_result.get("allowed"),
        "guardrail_reason": guardrail_result.get("reason"),
        "outcome": outcome,
        "decided_by": decided_by,
        "execution_id": execution_id or "",
        "execution_status": execution_status or "",
    }


def build_evidence_document(
    *,
    account_id: str,
    region: str,
    ledger_items: list[dict[str, Any]],
    period_start: str,
    period_end: str,
) -> dict[str, Any]:
    """Summarize a batch of ledger items into one grc-evidence-automation
    -shaped evidence document, scoped to a single account/region the way
    that tool's own AWS collectors are.
    """
    outcomes = Counter(item["outcome"] for item in ledger_items)
    executed_or_dry_run = [i for i in ledger_items if i["outcome"] in ("executed", "dry_run")]
    failed = [i for i in ledger_items if i["outcome"] == "failed"]
    controls = sorted({c for item in ledger_items for c in item.get("nist_controls", [])})

    status = "fail" if failed else ("pass" if ledger_items else "info")
    summary = (
        f"{len(ledger_items)} finding(s) evaluated between {period_start} and {period_end}; "
        f"{outcomes.get('executed', 0)} remediated, {outcomes.get('dry_run', 0)} dry-run, "
        f"{outcomes.get('blocked', 0)} blocked by guardrail, {outcomes.get('denied', 0)} denied, "
        f"{len(failed)} failed"
    )

    document: dict[str, Any] = {
        "account": account_id,
        "collected_at": period_end,
        "collector": "aws.remediation_orchestrator",
        "controls": {"nist_800_53": controls},
        "data": {
            "findings_evaluated": len(ledger_items),
            "remediated": outcomes.get("executed", 0),
            "dry_run": outcomes.get("dry_run", 0),
            "blocked_by_guardrail": outcomes.get("blocked", 0),
            "denied": outcomes.get("denied", 0),
            "failed": len(failed),
            "period_start": period_start,
            "period_end": period_end,
        },
        "findings": [
            {
                "message": f"{item['outcome']}: {item['title']}",
                "resource": item["resource_arn"] or item["resource_type"],
                "severity": item["severity_label"].lower(),
            }
            for item in executed_or_dry_run + failed
        ],
        "provider": "aws",
        "region": region,
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "status": status,
        "summary": summary,
        "title": "Automated remediation actions",
    }
    document["sha256"] = _sha256_of(document)
    return document


def _sha256_of(document: dict[str, Any]) -> str:
    canonical = json.dumps(document, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
