"""SSM Automation aws:executeScript step for IsolateCompromisedInstance.

Quarantines the EC2 instance named in a finding, in this order:

1. Tags the instance, so anyone looking at it sees it's under investigation.
2. Snapshots every attached EBS volume, for forensics, before anything
   else changes.
3. Finds or creates the VPC's isolation security group: no inbound
   rules, and its default allow-all egress rule revoked. One group per
   VPC, reused across incidents and found by tag.
4. Replaces the security groups on every network interface of the
   instance with that group. ModifyInstanceAttribute only reaches the
   primary interface, so a second interface would stay open.

Existing tracked connections can survive a security group change until
they close. Stop the instance (the document's StopInstance parameter) if
a live session must end now.

Ported from aws-cloud-security-toolbox's ec2-isolation-runbook, which
needed the isolation group created ahead of time in a VPC you named.
"""
import boto3

ISOLATION_TAG_KEY = "Purpose"
ISOLATION_TAG_VALUE = "incident-response-isolation"


def _isolation_group(ec2, vpc_id, name_prefix):
    existing = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": f"tag:{ISOLATION_TAG_KEY}", "Values": [ISOLATION_TAG_VALUE]},
        ]
    )["SecurityGroups"]
    if existing:
        return existing[0]["GroupId"]

    group_id = ec2.create_security_group(
        GroupName=f"{name_prefix}-isolation-{vpc_id}",
        Description="Incident-response quarantine: no inbound, no outbound.",
        VpcId=vpc_id,
        TagSpecifications=[{
            "ResourceType": "security-group",
            "Tags": [{"Key": ISOLATION_TAG_KEY, "Value": ISOLATION_TAG_VALUE}],
        }],
    )["GroupId"]
    ec2.revoke_security_group_egress(
        GroupId=group_id,
        IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    return group_id


def handler(events, _context):
    instance_id = events["ResourceArn"].rsplit("/", 1)[-1]
    finding_id = events.get("FindingId") or "unspecified"
    name_prefix = events["NamePrefix"]

    ec2 = boto3.client("ec2")
    reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    instance = reservations[0]["Instances"][0]

    ec2.create_tags(
        Resources=[instance_id],
        Tags=[
            {"Key": "IsolatedForIR", "Value": "true"},
            {"Key": "IsolationFindingId", "Value": finding_id[:256]},
        ],
    )

    snapshot_ids = []
    for mapping in instance.get("BlockDeviceMappings", []):
        volume_id = (mapping.get("Ebs") or {}).get("VolumeId")
        if not volume_id:
            continue
        snapshot = ec2.create_snapshot(
            VolumeId=volume_id,
            Description=f"IR isolation snapshot of {volume_id} from {instance_id}",
            TagSpecifications=[{
                "ResourceType": "snapshot",
                "Tags": [
                    {"Key": "SourceInstanceId", "Value": instance_id},
                    {"Key": "IsolationFindingId", "Value": finding_id[:256]},
                ],
            }],
        )
        snapshot_ids.append(snapshot["SnapshotId"])

    group_id = _isolation_group(ec2, instance["VpcId"], name_prefix)
    interface_ids = [eni["NetworkInterfaceId"] for eni in instance.get("NetworkInterfaces", [])]
    for interface_id in interface_ids:
        ec2.modify_network_interface_attribute(NetworkInterfaceId=interface_id, Groups=[group_id])

    return {
        "InstanceId": instance_id,
        "IsolationSecurityGroupId": group_id,
        "SnapshotIds": snapshot_ids,
        "NetworkInterfaceIds": interface_ids,
    }
