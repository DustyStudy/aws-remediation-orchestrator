"""SSM Automation aws:executeScript step for RevokeRoleSessions.

Revokes every active session of the IAM role behind a GuardDuty
credential finding, such as
UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS.
Stolen role credentials are temporary, so there are no access keys to
deactivate. They keep working until they expire unless the role denies
them.

It adds the same inline policy as the IAM console's "Revoke active
sessions" button: AWSRevokeOlderSessions, which denies every action to
credentials issued before now (aws:TokenIssueTime). Sessions issued
after it keep working, so the role stays usable. Running it again moves
the cutoff forward, which only revokes more.

This stops the stolen session, not whatever the attacker stole it from.
If the credentials came off an instance, isolate the instance too
(IsolateCompromisedInstance), or the attacker can fetch new ones.
Workloads that use the role fail until they get fresh credentials.
"""
import json
from datetime import datetime, timezone

import boto3

POLICY_NAME = "AWSRevokeOlderSessions"
MISSING = ("", "unspecified")


def _now():
    return datetime.now(timezone.utc)


def _revoke_policy(cutoff):
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Action": ["*"],
            "Resource": ["*"],
            "Condition": {"DateLessThan": {"aws:TokenIssueTime": cutoff}},
        }],
    }


def handler(events, _context):
    role_name = events.get("RoleName") or ""
    account_id = events.get("AccountId") or ""
    finding_id = events.get("FindingId") or "unspecified"

    if role_name in MISSING:
        raise ValueError(
            "The finding names no assumed-role principal, so there is no role to revoke. "
            "Use DisableCompromisedCredentials for IAM user keys."
        )

    # Role names repeat across accounts. Revoking a same-named role in the
    # wrong account would cause an outage and leave the real one untouched.
    own_account = boto3.client("sts").get_caller_identity()["Account"]
    if account_id not in MISSING and account_id != own_account:
        raise ValueError(
            f"The finding is for account {account_id}, but this automation runs in "
            f"{own_account}. Revoke the role from its own account."
        )

    # IAM refuses inline policies on these roles, so fail with the fix
    # instead of an AccessDenied.
    if role_name.startswith("AWSReservedSSO_"):
        raise ValueError(
            f"{role_name} is managed by IAM Identity Center. Remove the user's account "
            "assignment or permission set there instead."
        )

    iam = boto3.client("iam")
    role = iam.get_role(RoleName=role_name)["Role"]
    if role["Path"].startswith("/aws-service-role/"):
        raise ValueError(f"{role_name} is a service-linked role, which can't take an inline policy.")

    cutoff = _now().strftime("%Y-%m-%dT%H:%M:%SZ")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=POLICY_NAME,
        PolicyDocument=json.dumps(_revoke_policy(cutoff)),
    )
    iam.tag_role(
        RoleName=role_name,
        Tags=[
            {"Key": "SessionsRevokedAt", "Value": cutoff},
            {"Key": "RemediationFindingId", "Value": finding_id[:256]},
        ],
    )

    return {"RoleName": role_name, "RoleArn": role["Arn"], "RevokedBefore": cutoff}
