"""SSM Automation aws:executeScript step for DisableCompromisedCredentials.

Deactivates (never deletes - reversible, and preserves the key for
forensic review) every *active* access key belonging to the IAM user named
in a GuardDuty ``UnauthorizedAccess:IAMUser/*`` finding, and tags the user
so the deactivation is visible outside this system too.
"""
import boto3


def handler(events, _context):
    resource_arn = events["ResourceArn"]
    finding_id = events.get("FindingId", "unspecified")
    username = resource_arn.rsplit("/", 1)[-1]

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
            {"Key": "RemediationFindingId", "Value": finding_id},
        ],
    )

    return {"UserName": username, "DisabledAccessKeyIds": disabled_key_ids}
