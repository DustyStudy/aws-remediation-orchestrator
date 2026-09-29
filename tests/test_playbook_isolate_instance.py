from unittest.mock import MagicMock

import pytest

SCRIPT = "terraform/ssm-documents/scripts/isolate_instance.py"
INSTANCE_ARN = "arn:aws:ec2:us-east-1:123456789012:instance/i-1"


@pytest.fixture
def script(load_module, monkeypatch):
    module = load_module(SCRIPT)
    ec2 = MagicMock()
    ec2.describe_instances.return_value = {
        "Reservations": [{
            "Instances": [{
                "VpcId": "vpc-1",
                "BlockDeviceMappings": [
                    {"Ebs": {"VolumeId": "vol-1"}},
                    {"Ebs": {"VolumeId": "vol-2"}},
                    {"VirtualName": "ephemeral0"},
                ],
                "NetworkInterfaces": [{"NetworkInterfaceId": "eni-1"}, {"NetworkInterfaceId": "eni-2"}],
            }]
        }]
    }
    ec2.create_snapshot.side_effect = lambda **kwargs: {"SnapshotId": "snap-" + kwargs["VolumeId"]}
    ec2.describe_security_groups.return_value = {"SecurityGroups": [{"GroupId": "sg-iso"}]}
    monkeypatch.setattr(module.boto3, "client", lambda service: ec2)
    module.ec2 = ec2
    return module


def _run(script):
    return script.handler({"ResourceArn": INSTANCE_ARN, "FindingId": "f-1", "NamePrefix": "ro"}, None)


def test_snapshots_every_ebs_volume(script):
    result = _run(script)

    assert result["SnapshotIds"] == ["snap-vol-1", "snap-vol-2"]


def test_every_network_interface_gets_the_isolation_group(script):
    result = _run(script)

    calls = script.ec2.modify_network_interface_attribute.call_args_list
    assert [c.kwargs for c in calls] == [
        {"NetworkInterfaceId": "eni-1", "Groups": ["sg-iso"]},
        {"NetworkInterfaceId": "eni-2", "Groups": ["sg-iso"]},
    ]
    assert result["IsolationSecurityGroupId"] == "sg-iso"


def test_snapshots_happen_before_the_network_change(script):
    order = []
    script.ec2.create_snapshot.side_effect = lambda **kwargs: order.append("snapshot") or {"SnapshotId": "s"}
    script.ec2.modify_network_interface_attribute.side_effect = lambda **kwargs: order.append("isolate")

    _run(script)

    assert order.index("isolate") > max(i for i, step in enumerate(order) if step == "snapshot")


def test_existing_isolation_group_is_reused(script):
    _run(script)

    script.ec2.create_security_group.assert_not_called()
    filters = script.ec2.describe_security_groups.call_args.kwargs["Filters"]
    assert {"Name": "vpc-id", "Values": ["vpc-1"]} in filters


def test_missing_isolation_group_is_created_with_no_egress(script):
    script.ec2.describe_security_groups.return_value = {"SecurityGroups": []}
    script.ec2.create_security_group.return_value = {"GroupId": "sg-new"}

    result = _run(script)

    assert script.ec2.create_security_group.call_args.kwargs["VpcId"] == "vpc-1"
    script.ec2.revoke_security_group_egress.assert_called_once_with(
        GroupId="sg-new",
        IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    assert result["IsolationSecurityGroupId"] == "sg-new"


def test_instance_is_tagged_with_the_finding(script):
    _run(script)

    tags = script.ec2.create_tags.call_args.kwargs["Tags"]
    assert {"Key": "IsolationFindingId", "Value": "f-1"} in tags
