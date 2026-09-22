"""Policy registry matching: which playbook (if any) applies to a finding.

The registry is a small DynamoDB table (rarely more than a few dozen items)
rather than anything requiring an index - each item is a prefix match
against either the finding's first ``Types`` entry or its ``GeneratorId``,
plus the governance metadata (mode, target SSM document, NIST mapping,
rate limit) that decides what happens next.

See docs/POLICY_REGISTRY.md for the item schema and worked examples,
including how to point ``action_document`` at an SSM document owned by a
different repo (e.g. aws-cloud-security-toolbox) instead of one this repo
ships.
"""
from __future__ import annotations

from typing import Any

DEFAULT_POLICY_ID = "default"

VALID_MODES = ("auto", "approval_required", "dry_run", "ignore")


class InvalidPolicyError(ValueError):
    pass


def validate_policy(item: dict[str, Any]) -> None:
    mode = item.get("mode")
    if mode not in VALID_MODES:
        raise InvalidPolicyError(f"policy {item.get('match_id')!r} has invalid mode {mode!r}")
    if mode in ("auto", "approval_required") and not item.get("action_document"):
        raise InvalidPolicyError(
            f"policy {item.get('match_id')!r} has mode {mode!r} but no action_document"
        )


def select_policy(items: list[dict[str, Any]], normalized: dict[str, Any]) -> dict[str, Any]:
    """Pick the best-matching policy item for a normalized finding.

    Matching is prefix-based on either ``type_prefix`` or ``generator_id``,
    per item. When multiple items match, the one with the longest
    ``match_value`` wins (most specific rule beats a broader one covering
    the same finding). Falls back to the ``default`` item, which every
    deployment must seed (Terraform does this - see dynamodb.tf) so a
    finding never has literally no policy.
    """
    best: dict[str, Any] | None = None
    for item in items:
        if item.get("match_id") == DEFAULT_POLICY_ID:
            continue
        field = item.get("match_field")
        value = item.get("match_value", "")
        subject = normalized.get(field, "") if field else ""
        if not value or not subject.startswith(value):
            continue
        if best is None or len(value) > len(best.get("match_value", "")):
            best = item

    if best is not None:
        return best

    for item in items:
        if item.get("match_id") == DEFAULT_POLICY_ID:
            return item

    raise InvalidPolicyError(
        "no policy matched and no 'default' policy item exists in the registry"
    )
