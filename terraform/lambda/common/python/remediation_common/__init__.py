"""Shared helpers used by every Lambda in the remediation orchestrator.

Packaged as a single Lambda layer (see ``terraform/lambda-layer.tf``) so the
ASFF-parsing, guardrail, and ledger logic lives in one place instead of being
copy-pasted into each function - the state machine's steps are thin handlers
that call into this package.
"""
