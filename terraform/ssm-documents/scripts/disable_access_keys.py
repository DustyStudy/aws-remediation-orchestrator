"""SSM Automation aws:executeScript step for DisableCompromisedCredentials.

Deactivates (never deletes - reversible, and preserves the key for
forensic review) every *active* access key belonging to the IAM user named
in a GuardDuty ``UnauthorizedAccess:IAMUser/*`` finding, and tags the user
so the deactivation is visible outside this system too.

The user comes from the finding's AwsIamAccessKey resource (UserName).
ResourceArn is only used when it is an IAM user ARN: for GuardDuty
findings it's the access key ID or an EC2 instance, not the user.
GuardDuty says "IAMUser" for roles too, so a finding with no IAM user is
refused rather than guessed at. RevokeRoleSessions handles roles.
"""
import boto3

MISSING = ("", "unspecified")


def _user_name(events):
    user_name = events.get("UserName") or ""
    if user_name not in MISSING:
        return user_name
    resource_arn = events.get("ResourceArn") or ""
    if resource_arn.startswith("arn:") and ":user/" in resource_arn:
        return resource_arn.rsplit("/", 1)[-1]
    raise ValueError(
        "The finding names no IAM user. If the principal is a role, use RevokeRoleSessions."
    )


def handler(events, _context):
    finding_id = events.get("FindingId") or "unspecified"
    account_id = events.get("AccountId") or ""
    username = _user_name(events)

    # User names repeat across accounts. Deactivating a same-named user's
    # keys in the wrong account would leave the real ones active.
    own_account = boto3.client("sts").get_caller_identity()["Account"]
    if account_id not in MISSING and account_id != own_account:
        raise ValueError(
            f"The finding is for account {account_id}, but this automation runs in "
            f"{own_account}. Disable the keys from their own account."
        )

    iam = boto3.client("iam")
    keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]

    disabled_key_ids = []
    for key in keys:
        if key["Status"] == "Active":
            iam.update_access_key(
                UserName=username, AccessKeyId=key["AccessKeyId"], Status="Inactive"
            )
            disabled_key_ids.append(key["AccessKeyId"])

    iam.tag_user(
        UserName=username,
        Tags=[
            {"Key": "CompromisedCredentials", "Value": "true"},
            {"Key": "RemediationFindingId", "Value": finding_id[:256]},
        ],
    )

    return {"UserName": username, "DisabledAccessKeyIds": disabled_key_ids}
