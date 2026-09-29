import json
from unittest.mock import MagicMock

import pytest

SCRIPT = "terraform/ssm-documents/scripts/revoke_open_ssh_rdp.py"
SG_ARN = "arn:aws:ec2:us-east-1:123456789012:security-group/sg-1"


@pytest.fixture
def script(load_module, monkeypatch):
    module = load_module(SCRIPT)
    ec2 = MagicMock()
    monkeypatch.setattr(module.boto3, "client", lambda service: ec2)
    module.ec2 = ec2
    return module


def _rule(protocol, from_port, to_port, v4=(), v6=()):
    rule = {
        "IpProtocol": protocol,
        "IpRanges": [{"CidrIp": c} for c in v4],
        "Ipv6Ranges": [{"CidrIpv6": c} for c in v6],
    }
    if from_port is not None:
        rule["FromPort"], rule["ToPort"] = from_port, to_port
    return rule


def _run(script, *rules):
    script.ec2.describe_security_groups.return_value = {"SecurityGroups": [{"IpPermissions": list(rules)}]}
    return script.handler({"ResourceArn": SG_ARN}, None)


def _revoked(script):
    if not script.ec2.revoke_security_group_ingress.called:
        return []
    return script.ec2.revoke_security_group_ingress.call_args.kwargs["IpPermissions"]


def test_revokes_only_the_internet_cidr_on_ssh(script):
    result = _run(script, _rule("tcp", 22, 22, v4=["0.0.0.0/0", "10.0.0.0/8"]))

    assert _revoked(script) == [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    assert script.ec2.revoke_security_group_ingress.call_args.kwargs["GroupId"] == "sg-1"
    assert json.loads(result["RevokedRules"]) == _revoked(script)


def test_revokes_ipv6_rdp(script):
    _run(script, _rule("tcp", 3389, 3389, v6=["::/0"]))

    assert _revoked(script)[0]["Ipv6Ranges"] == [{"CidrIpv6": "::/0"}]


def test_port_range_covering_ssh_is_revoked(script):
    _run(script, _rule("tcp", 0, 1024, v4=["0.0.0.0/0"]))

    assert len(_revoked(script)) == 1


def test_all_traffic_rule_is_revoked_without_ports(script):
    _run(script, _rule("-1", None, None, v4=["0.0.0.0/0"]))

    revoked = _revoked(script)[0]
    assert revoked["IpProtocol"] == "-1"
    assert "FromPort" not in revoked and "ToPort" not in revoked


def test_https_to_the_internet_is_left_alone(script):
    result = _run(script, _rule("tcp", 443, 443, v4=["0.0.0.0/0"]))

    script.ec2.revoke_security_group_ingress.assert_not_called()
    assert result["RevokedRules"] == "[]"


def test_ssh_from_a_private_range_is_left_alone(script):
    _run(script, _rule("tcp", 22, 22, v4=["10.0.0.0/8"]))

    script.ec2.revoke_security_group_ingress.assert_not_called()


def test_missing_group_revokes_nothing(script):
    script.ec2.describe_security_groups.return_value = {"SecurityGroups": []}

    result = script.handler({"ResourceArn": SG_ARN}, None)

    script.ec2.revoke_security_group_ingress.assert_not_called()
    assert result["GroupId"] == "sg-1"
