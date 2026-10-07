"""Live test of the IAM-user and instance playbooks, and of deny and timeout.

Runs against the same examples/org-mode deployment as live_test.py and
covers what that script leaves out:

* DisableCompromisedCredentials, DeactivateStaleAccessKeys (member-a)
* IsolateCompromisedInstance (member-b)
* an approval request that is denied, and one left to time out (member-a)

    python live_test_playbooks.py setup   --hub P --member-a P --member-b P [--management P]
    python live_test_playbooks.py send    ...   # the three playbooks, plus the two approval requests
    python live_test_playbooks.py deny    ...   # opens the Deny link of the first request
    python live_test_playbooks.py collect ...   # after approval_timeout_seconds; writes the evidence file
    python live_test_playbooks.py cleanup ...

The deployment needs the three playbook policies from
terraform.tfvars.example in auto mode, a short approval_timeout_seconds,
and stale_key_max_age_days = -1: an access key cannot be backdated, so the
threshold is lowered until a key created minutes ago counts as stale.

--management is for organizations whose SCPs deny IAM users in member
accounts. The users and their access keys are then created by a
service-managed StackSet from that profile (the StackSets execution role
must be exempt from the SCP), and no secret access key leaves
CloudFormation. Without it they are created directly and the secrets are
discarded.

The approval requests are read from an SQS queue subscribed to the
notifications topic, so the test does not depend on an inbox.
"""
import argparse
import json
import re
import subprocess
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import live_test
from live_test import VICTIM_ROLE, Account, ledger_entries

STATE = Path(__file__).with_name(".live-test-playbooks-state.json")
EVIDENCE = Path(__file__).with_name("live-test-playbooks-evidence.json")
STACK_SET = "orch-live-test-users"
QUEUE = "orch-live-test-approvals"
EXEMPT_TAG = "break-glass"
USERS = {"compromised": "live-test-compromised", "stale": "live-test-stale", "exempt": "live-test-exempt"}
ROLE_FINDING_TYPE = "Effects/Data Exfiltration/UnauthorizedAccess:IAMUser-InstanceCredentialExfiltration.OutsideAWS"


def outputs():
    return json.loads(subprocess.run(
        ["terraform", "output", "-json", "orchestrator"], check=True, capture_output=True, text=True,
        cwd=Path(__file__).parent).stdout)


def user_template():
    resources = {}
    for label, name in USERS.items():
        tags = [{"Key": EXEMPT_TAG, "Value": "true"}] if label == "exempt" else []
        resources[f"{label.title()}User"] = {"Type": "AWS::IAM::User", "Properties": {"UserName": name, "Tags": tags}}
        resources[f"{label.title()}Key"] = {
            "Type": "AWS::IAM::AccessKey", "Properties": {"UserName": {"Ref": f"{label.title()}User"}}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


def wait_for_stack_set(cloudformation, operation_id):
    while True:
        status = cloudformation.describe_stack_set_operation(
            StackSetName=STACK_SET, OperationId=operation_id)["StackSetOperation"]["Status"]
        if status not in ("RUNNING", "QUEUED"):
            assert status == "SUCCEEDED", f"StackSet operation {status}"
            return
        time.sleep(10)


def stack_set_targets(management, account):
    parent = management.client("organizations").list_parents(ChildId=account.id)["Parents"][0]["Id"]
    return {"OrganizationalUnitIds": [parent], "Accounts": [account.id], "AccountFilterType": "INTERSECTION"}


def create_users(management, a):
    if management:
        cloudformation = management.client("cloudformation")
        cloudformation.create_stack_set(
            StackSetName=STACK_SET, Description="live_test_playbooks.py targets. Delete after the run.",
            TemplateBody=user_template(), Capabilities=["CAPABILITY_NAMED_IAM"],
            PermissionModel="SERVICE_MANAGED", AutoDeployment={"Enabled": False})
        RUN["stack_set"] = True
        wait_for_stack_set(cloudformation, cloudformation.create_stack_instances(
            StackSetName=STACK_SET, DeploymentTargets=stack_set_targets(management, a),
            Regions=[a.region])["OperationId"])
    else:
        iam = a.client("iam")
        for label, name in USERS.items():
            iam.create_user(UserName=name, Tags=[{"Key": EXEMPT_TAG, "Value": "true"}] if label == "exempt" else [])
            iam.create_access_key(UserName=name)  # the secret is never stored
    print(f"created {sorted(USERS.values())} in {a.label}, one active access key each")


def setup(hub, a, b, management):
    RUN["run_id"] = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    create_users(management, a)

    a.client("iam").create_role(
        RoleName=VICTIM_ROLE,
        Description="live_test_playbooks.py target for the denied and timed-out requests. No permissions.",
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}),
    )

    ami = b.client("ssm").get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")["Parameter"]["Value"]
    ec2 = b.client("ec2")
    instance = ec2.run_instances(
        ImageId=ami, InstanceType="t3.nano", MinCount=1, MaxCount=1, MetadataOptions={"HttpTokens": "required"},
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "orch-live-test"}]}],
    )["Instances"][0]
    RUN["instance"] = instance["InstanceId"]
    ec2.get_waiter("instance_running").wait(InstanceIds=[RUN["instance"]])
    RUN["instance_groups_before"] = [g["GroupName"] for g in instance["SecurityGroups"]]
    print(f"launched {RUN['instance']} in {b.label} with {RUN['instance_groups_before']}")

    sqs = hub.client("sqs")
    topic = outputs()["notification_topic_arn"]
    queue_url = sqs.create_queue(QueueName=QUEUE)["QueueUrl"]
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage",
            "Resource": queue_arn, "Condition": {"ArnEquals": {"aws:SourceArn": topic}}}]})})
    RUN["subscription"] = hub.client("sns").subscribe(
        TopicArn=topic, Protocol="sqs", Endpoint=queue_arn, ReturnSubscriptionArn=True)["SubscriptionArn"]
    RUN["queue_url"] = queue_url
    print(f"subscribed {QUEUE} to the notifications topic")


def role_finding(a, name):
    a.import_finding(
        name, "live-test/guardduty-shaped", f"Live test: role credentials used from outside AWS ({name})",
        {"Type": "AwsIamAccessKey", "Id": "AWS::IAM::AccessKey:ASIALIVETESTEXAMPLE", "Region": a.region,
         "Details": {"AwsIamAccessKey": {"PrincipalType": "AssumedRole", "PrincipalName": VICTIM_ROLE}}},
        types=[ROLE_FINDING_TYPE])


def send(_hub, a, b, _management):
    def user_arn(label):
        return f"arn:{a.partition}:iam::{a.id}:user/{USERS[label]}"

    a.import_finding(
        "compromised-credentials", "live-test/guardduty-shaped",
        "API was invoked from a known malicious IP address",
        {"Type": "AwsIamAccessKey", "Id": "AWS::IAM::AccessKey:AKIALIVETESTEXAMPLE", "Region": a.region,
         "Details": {"AwsIamAccessKey": {"PrincipalType": "IAMUser", "PrincipalName": USERS["compromised"]}}},
        types=["TTPs/UnauthorizedAccess:IAMUser-MaliciousIPCaller.Custom"])
    for label in ("stale", "exempt"):
        a.import_finding(
            f"stale-keys-{label}", "security-control/IAM.3", "IAM users' access keys should be rotated every 90 days or less",
            {"Type": "AwsIamUser", "Id": user_arn(label), "Region": a.region}, severity="MEDIUM")
    b.import_finding(
        "compromised-instance", "live-test/guardduty-shaped",
        "The EC2 instance is querying a domain name associated with a known command and control server",
        {"Type": "AwsEc2Instance", "Region": b.region,
         "Id": f"arn:{b.partition}:ec2:{b.region}:{b.id}:instance/{RUN['instance']}"},
        types=["TTPs/Command and Control/Backdoor:EC2-C&CActivity.B!DNS"])
    role_finding(a, "approval-denied")
    role_finding(a, "approval-timeout")
    print("Run deny next. The timed-out request needs approval_timeout_seconds before collect.")


def deny(hub, _a, _b, _management):
    """Open the Deny link of the approval-denied request, as the person reading the message would."""
    sqs = hub.client("sqs")
    deadline = time.time() + 300
    while time.time() < deadline:
        for message in sqs.receive_message(
                QueueUrl=RUN["queue_url"], MaxNumberOfMessages=10, WaitTimeSeconds=20).get("Messages", []):
            body = json.loads(message["Body"])
            link = re.search(r"Deny:\s+(\S+)", body.get("Message", ""))
            if link and "(approval-denied)" in body.get("Subject", "") + body["Message"]:
                with urllib.request.urlopen(link.group(1), timeout=30) as response:
                    RUN["deny_response"] = {"status": response.status, "body": response.read().decode()[:300]}
                print(f"opened the Deny link: HTTP {response.status}")
                return
    raise SystemExit("no approval request for approval-denied arrived in five minutes")


def collect(hub, a, b, _management):
    accounts = {x.label: x for x in (hub, a, b)}
    out = outputs()
    results = {}
    for name, finding in RUN["findings"].items():
        owner = accounts[finding["account"]]
        entries = ledger_entries(hub, out["ledger_table"], finding["id"], wait_seconds=180)
        result = {"finding_account": owner.label, "ledger": entries}
        for entry in entries:
            if entry.get("execution_id"):
                # Looked up with the finding account's own credentials: the
                # automation exists there only if it ran there.
                execution = owner.client("ssm").get_automation_execution(
                    AutomationExecutionId=entry["execution_id"])["AutomationExecution"]
                result["automation"] = {
                    "ran_in": owner.label,
                    "document": execution["DocumentName"],
                    "status": execution["AutomationExecutionStatus"],
                    "executed_by": execution["ExecutedBy"],
                    "steps": {s["StepName"]: s["StepStatus"] for s in execution["StepExecutions"]},
                }
        results[name] = result
        print(name, [(e["policy_id"], e["outcome"], e.get("decided_by")) for e in entries] or "NO LEDGER ENTRY")

    iam = a.client("iam")
    users = {
        label: {
            "access_keys": [k["Status"] for k in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]],
            "tags": sorted(t["Key"] for t in iam.list_user_tags(UserName=name)["Tags"]),
        } for label, name in USERS.items()}

    ec2 = b.client("ec2")
    instance = ec2.describe_instances(InstanceIds=[RUN["instance"]])["Reservations"][0]["Instances"][0]
    groups = ec2.describe_security_groups(
        GroupIds=[g["GroupId"] for eni in instance["NetworkInterfaces"] for g in eni["Groups"]])["SecurityGroups"]
    snapshots = ec2.describe_snapshots(
        OwnerIds=["self"], Filters=[{"Name": "tag:SourceInstanceId", "Values": [RUN["instance"]]}])["Snapshots"]
    state_after = {
        "users": users,
        "victim_role_inline_policies": iam.list_role_policies(RoleName=VICTIM_ROLE)["PolicyNames"],
        "instance": {
            "state": instance["State"]["Name"],
            "tags": sorted(t["Key"] for t in instance.get("Tags", [])),
            "security_groups_before": RUN["instance_groups_before"],
            "security_groups_after": [
                {"tags": {t["Key"]: t["Value"] for t in g.get("Tags", [])},
                 "ingress_rules": len(g["IpPermissions"]), "egress_rules": len(g["IpPermissionsEgress"])}
                for g in groups],
            "snapshots": [{"state": s["State"], "volume_gb": s["VolumeSize"]} for s in snapshots],
        },
        "deny_link_response": RUN.get("deny_response"),
    }

    evidence = {"run_id": RUN["run_id"], "accounts": {x.label: x.id for x in accounts.values()},
                "findings": results, "resource_state_after": state_after}
    text = json.dumps(evidence, indent=2, default=str)
    for account in accounts.values():  # account IDs never go in the repo
        text = text.replace(account.id, f"<{account.label}>")
    assert not re.search(r"\b\d{12}\b", text), "unmasked account ID in evidence"
    EVIDENCE.write_text(text, encoding="utf-8")
    print(f"wrote {EVIDENCE}")


def cleanup(hub, a, b, management):
    accounts = {x.label: x for x in (hub, a, b)}
    for finding in RUN.get("findings", {}).values():
        owner = accounts[finding["account"]]
        owner.client("securityhub").batch_update_findings(
            FindingIdentifiers=[{
                "Id": finding["id"],
                "ProductArn": f"arn:{owner.partition}:securityhub:{owner.region}:{owner.id}:product/{owner.id}/default"}],
            Workflow={"Status": "RESOLVED"}, Note={"Text": "live test cleanup", "UpdatedBy": "live_test_playbooks.py"})

    if RUN.get("stack_set"):
        cloudformation = management.client("cloudformation")
        wait_for_stack_set(cloudformation, cloudformation.delete_stack_instances(
            StackSetName=STACK_SET, DeploymentTargets=stack_set_targets(management, a),
            Regions=[a.region], RetainStacks=False)["OperationId"])
        cloudformation.delete_stack_set(StackSetName=STACK_SET)
    else:
        iam = a.client("iam")
        for name in USERS.values():
            for key in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
                iam.delete_access_key(UserName=name, AccessKeyId=key["AccessKeyId"])
            iam.delete_user(UserName=name)

    iam = a.client("iam")
    for policy in iam.list_role_policies(RoleName=VICTIM_ROLE)["PolicyNames"]:
        iam.delete_role_policy(RoleName=VICTIM_ROLE, PolicyName=policy)
    iam.delete_role(RoleName=VICTIM_ROLE)

    ec2 = b.client("ec2")
    instance = ec2.describe_instances(InstanceIds=[RUN["instance"]])["Reservations"][0]["Instances"][0]
    isolation_groups = [g["GroupId"] for g in instance.get("SecurityGroups", []) if "-isolation-" in g["GroupName"]]
    ec2.terminate_instances(InstanceIds=[RUN["instance"]])
    ec2.get_waiter("instance_terminated").wait(InstanceIds=[RUN["instance"]])
    for snapshot in ec2.describe_snapshots(
            OwnerIds=["self"], Filters=[{"Name": "tag:SourceInstanceId", "Values": [RUN["instance"]]}])["Snapshots"]:
        ec2.delete_snapshot(SnapshotId=snapshot["SnapshotId"])
    for group in isolation_groups:
        ec2.delete_security_group(GroupId=group)

    hub.client("sns").unsubscribe(SubscriptionArn=RUN["subscription"])
    hub.client("sqs").delete_queue(QueueUrl=RUN["queue_url"])
    print("deleted the users, role, instance, snapshots, isolation group and queue; resolved the findings")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("stage", choices=["setup", "send", "deny", "collect", "cleanup"])
    parser.add_argument("--hub", required=True, help="profile for the hub account")
    parser.add_argument("--member-a", required=True, help="profile for the first member account")
    parser.add_argument("--member-b", required=True, help="profile for the second member account")
    parser.add_argument("--management", help="profile for the organization management account; see above")
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()

    RUN = json.loads(STATE.read_text()) if STATE.exists() else {"findings": {}}
    live_test.RUN = RUN  # Account.import_finding records into it
    try:
        globals()[args.stage](
            Account("hub", args.hub, args.region),
            Account("member-a", args.member_a, args.region),
            Account("member-b", args.member_b, args.region),
            Account("management", args.management, args.region).session if args.management else None,
        )
    finally:
        STATE.write_text(json.dumps(RUN, indent=2))
