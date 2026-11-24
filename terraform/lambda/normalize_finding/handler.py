"""Normalize every finding for the bounded Map state, retaining rejected inputs."""
from __future__ import annotations

from typing import Any

from remediation_common import batch


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    return {"findings": batch.normalize_event(event)}
