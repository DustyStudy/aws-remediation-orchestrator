"""SSM Automation aws:executeScript step for RevokeOpenSshRdpIngress.

Revokes every ingress rule on the flagged security group that opens SSH
(22) or RDP (3389) to the whole internet (0.0.0.0/0 or ::/0). Rules from
narrower CIDRs, and internet-facing rules on other ports, are left alone.
A rule whose port range covers 22 or 3389 (or an all-traffic rule) counts
as opening them.

Ported from aws-cloud-security-toolbox's auto-remediate-open-ssh-rdp
Lambda, minus its CloudTrail event path: here the trigger is always a
Security Hub finding, so the script re-reads the group's current rules
instead of trusting the event.
"""
import json

import boto3

RISKY_PORTS = (22, 3389)
RISKY_CIDR_V4 = "0.0.0.0/0"
RISKY_CIDR_V6 = "::/0"


def _opens_risky_port(permission):
    protocol = str(permission.get("IpProtocol"))
    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    if protocol == "-1" or from_port is None or to_port is None:
        return True
    return any(from_port <= port <= to_port for port in RISKY_PORTS)


def risky_permissions(ip_permissions):
    """Return the subset of each rule to revoke, in the flat API shape
    revoke_security_group_ingress expects."""
    to_revoke = []
    for permission in ip_permissions:
        if not _opens_risky_port(permission):
            continue
        bad_v4 = [r for r in permission.get("IpRanges", []) if r.get("CidrIp") == RISKY_CIDR_V4]
        bad_v6 = [r for r in permission.get("Ipv6Ranges", []) if r.get("CidrIpv6") == RISKY_CIDR_V6]
        if not bad_v4 and not bad_v6:
            continue

        revoke = {"IpProtocol": permission.get("IpProtocol", "tcp")}
        # An all-traffic rule has no ports, and passing FromPort/ToPort as
        # None fails boto3 parameter validation.
        if str(revoke["IpProtocol"]) != "-1":
            for key in ("FromPort", "ToPort"):
                if permission.get(key) is not None:
                    revoke[key] = permission[key]
        if bad_v4:
            revoke["IpRanges"] = [{"CidrIp": RISKY_CIDR_V4}]
        if bad_v6:
            revoke["Ipv6Ranges"] = [{"CidrIpv6": RISKY_CIDR_V6}]
        to_revoke.append(revoke)
    return to_revoke


def handler(events, _context):
    # Security Hub reports a security group as
    # arn:<partition>:ec2:<region>:<account>:security-group/sg-...
    group_id = events["ResourceArn"].rsplit("/", 1)[-1]

    ec2 = boto3.client("ec2")
    groups = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"]
    to_revoke = risky_permissions(groups[0].get("IpPermissions", [])) if groups else []

    if to_revoke:
        ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=to_revoke)

    return {"GroupId": group_id, "RevokedRules": json.dumps(to_revoke)}
