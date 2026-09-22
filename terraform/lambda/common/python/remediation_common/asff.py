"""Normalize an AWS Security Finding Format (ASFF) record.

Security Hub is the ingestion point: GuardDuty, Config, Inspector, Macie,
IAM Access Analyzer, and third-party findings (Wiz, etc.) all land here as
ASFF, so normalizing against ASFF - rather than each source's native shape -
lets one state machine handle any of them.
"""
from __future__ import annotations

from typing import Any


class MalformedFindingError(ValueError):
    """Raised when a Security Hub finding is missing fields we require."""


def normalize(finding: dict[str, Any]) -> dict[str, Any]:
    """Reduce a raw ASFF finding to the fields the state machine needs.

    Deliberately narrow: this is not a general-purpose ASFF parser, it's the
    subset of fields the policy registry, guardrails, and ledger actually
    key on. Extend it as new policies need more signal.
    """
    try:
        finding_id = finding["Id"]
        product_arn = finding["ProductArn"]
        title = finding["Title"]
        types = finding.get("Types") or []
        generator_id = finding["GeneratorId"]
        severity = finding.get("Severity", {})
        severity_label = severity.get("Label", "INFORMATIONAL")
        workflow_status = finding.get("Workflow", {}).get("Status", "NEW")
        record_state = finding.get("RecordState", "ACTIVE")
        aws_account_id = finding["AwsAccountId"]
        region = finding.get("Region") or _region_from_arn(product_arn)
        resources = finding.get("Resources") or []
    except KeyError as exc:
        raise MalformedFindingError(f"finding missing required field: {exc}") from exc

    primary_resource = resources[0] if resources else {}

    return {
        "finding_id": finding_id,
        "title": title,
        "types": types,
        "type_prefix": types[0] if types else "",
        "generator_id": generator_id,
        "severity_label": severity_label,
        "workflow_status": workflow_status,
        "record_state": record_state,
        "account_id": aws_account_id,
        "region": region,
        "resource_arn": primary_resource.get("Id", ""),
        "resource_type": primary_resource.get("Type", "Other"),
        "resource_tags": primary_resource.get("Tags") or {},
        "first_observed_at": finding.get("FirstObservedAt", finding.get("CreatedAt", "")),
        "description": finding.get("Description", ""),
    }


def should_process(normalized: dict[str, Any]) -> bool:
    """Filter out findings the state machine shouldn't act on at all.

    Archived/suppressed findings and ones already worked (workflow status
    other than NEW) are noise here - Security Hub, not this system, is the
    source of truth for triage state.
    """
    return normalized["record_state"] == "ACTIVE" and normalized["workflow_status"] in (
        "NEW",
        "NOTIFIED",
    )


SEVERITY_ORDER = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def meets_severity_threshold(severity_label: str, threshold: str | None) -> bool:
    """True if ``severity_label`` is at or above ``threshold`` (None = no floor)."""
    if not threshold:
        return True
    try:
        return SEVERITY_ORDER.index(severity_label) >= SEVERITY_ORDER.index(threshold)
    except ValueError:
        # Unknown label - fail open to "meets threshold" so an unrecognized
        # severity doesn't silently get skipped; the ledger entry still
        # records the raw label for a human to notice.
        return True


def _region_from_arn(arn: str) -> str:
    parts = arn.split(":")
    return parts[3] if len(parts) > 3 else ""
