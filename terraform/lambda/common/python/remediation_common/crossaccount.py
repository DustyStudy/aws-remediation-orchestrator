"""Org mode: credentials for acting in the account a finding came from.

The orchestrator runs in one account (the hub, normally the Security Hub
delegated administrator) and receives findings for every member account.
A playbook has to run in the account that owns the resource, so the hub
assumes a role there. modules/playbook-roles creates those roles, each
trusting exactly one hub function.
"""
from __future__ import annotations

from typing import Any

SESSION_NAME = "remediation-orchestrator"


def member_client_kwargs(
    sts_client: Any, function_arn: str, account_id: str, role_name: str
) -> dict[str, str] | None:
    """boto3 client kwargs for ``account_id``, or None to stay in this
    account: the finding is for this account, or org mode is off (no role
    name configured).
    """
    partition, own_account = _partition_and_account(function_arn)
    if not role_name or not account_id or account_id == own_account:
        return None

    credentials = sts_client.assume_role(
        RoleArn=f"arn:{partition}:iam::{account_id}:role/{role_name}",
        RoleSessionName=SESSION_NAME,
    )["Credentials"]
    return {
        "aws_access_key_id": credentials["AccessKeyId"],
        "aws_secret_access_key": credentials["SecretAccessKey"],
        "aws_session_token": credentials["SessionToken"],
    }


def is_onboarded(function_arn: str, account_id: str, member_account_ids: list[str]) -> bool:
    """True when the orchestrator can act in ``account_id``. Outside org
    mode (no member accounts) every finding is handled in this account,
    as it always was.
    """
    if not member_account_ids:
        return True
    _, own_account = _partition_and_account(function_arn)
    return account_id == own_account or account_id in member_account_ids


def _partition_and_account(function_arn: str) -> tuple[str, str]:
    # arn:<partition>:lambda:<region>:<account>:function:<name>
    parts = function_arn.split(":")
    return parts[1], parts[4]
