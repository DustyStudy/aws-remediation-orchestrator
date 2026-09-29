"""SSM Automation aws:executeScript step for DeactivateStaleAccessKeys.

Deactivates (never deletes) the stale access keys of the IAM user named in
a finding such as Security Hub IAM.3 (keys not rotated) or IAM.22
(credentials unused). A key is stale when it is older than MaxKeyAgeDays,
or has gone unused (or was never used) for more than MaxUnusedDays. Keys
that are still fresh stay active, unlike DisableCompromisedCredentials,
which deactivates every key.

A user carrying ExemptTagKey (any value) is skipped entirely: use it for
break-glass accounts that hold long-lived keys on purpose. If the user's
tags can't be read, the script fails instead of guessing.

Ported from aws-cloud-security-toolbox's iam-credential-hygiene, which
scanned every user on a schedule instead of acting per finding.
"""
from datetime import datetime, timezone

import boto3


def _days_since(moment, now):
    return (now - moment).days


def stale_reason(key, last_used, max_age_days, max_unused_days, now):
    """Return why an active key is stale, or None if it should stay."""
    age_days = _days_since(key["CreateDate"], now)
    if age_days > max_age_days:
        return f"age {age_days}d > {max_age_days}d"
    unused_days = _days_since(last_used, now) if last_used else age_days
    if unused_days > max_unused_days:
        used = "unused" if last_used else "never used"
        return f"{used} for {unused_days}d > {max_unused_days}d"
    return None


def handler(events, _context):
    user_name = events["ResourceArn"].rsplit("/", 1)[-1]
    max_age_days = int(events["MaxKeyAgeDays"])
    max_unused_days = int(events["MaxUnusedDays"])
    exempt_tag_key = events.get("ExemptTagKey") or ""

    iam = boto3.client("iam")
    if exempt_tag_key:
        tags = iam.list_user_tags(UserName=user_name)["Tags"]
        if any(tag["Key"] == exempt_tag_key for tag in tags):
            return {"UserName": user_name, "DeactivatedAccessKeyIds": [], "Reasons": "user is exempt"}

    now = datetime.now(timezone.utc)
    deactivated, reasons = [], []
    for key in iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]:
        if key["Status"] != "Active":
            continue
        last_used = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])["AccessKeyLastUsed"].get(
            "LastUsedDate"
        )
        reason = stale_reason(key, last_used, max_age_days, max_unused_days, now)
        if reason:
            iam.update_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"], Status="Inactive")
            deactivated.append(key["AccessKeyId"])
            reasons.append(f"{key['AccessKeyId']}: {reason}")

    return {
        "UserName": user_name,
        "DeactivatedAccessKeyIds": deactivated,
        "Reasons": "; ".join(reasons) or "no stale keys",
    }
