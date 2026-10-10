"""Live test for an org-mode deployment (examples/org-mode).

Creates deliberately non-compliant throwaway resources in the hub and two
member accounts, sends findings about them through Security Hub, and
records what the orchestrator did. docs/PROOF.md is written from its
output.

    python live_test.py setup    --hub P --member-a P --member-b P
    python live_test.py auto     ...   # auto, denylist, not-onboarded, real GuardDuty sample
    python live_test.py approval ...   # then click Approve in the email
    python live_test.py breaker  ...   # rate limit, then the circuit breaker
    python live_test.py collect  ...   # writes live-test-evidence.json
    python live_test.py cleanup  ...

AWS Config is not required. The control findings (S3.8, EC2.13) are
imported with BatchImportFindings in the account that owns the resource,
shaped like Security Hub's own, so the path from the member account's
Security Hub to the hub is the real one. The resources and every action
taken on them are real.

--outside is optional: a profile for an account in the organization that
is NOT in member_account_ids, to show its findings are blocked.
"""
import argparse
import json
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import boto3

STATE = Path(__file__).with_name(".live-test-state.json")
EVIDENCE = Path(__file__).with_name("live-test-evidence.json")
VICTIM_ROLE = "live-test-victim-role"
OPEN_RULES = [(22, "0.0.0.0/0"), (5432, "0.0.0.0/0"), (443, "0.0.0.0/0"), (22, "10.0.0.0/8")]
BPA_OFF = dict.fromkeys(("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"), False)


class Account:
    def __init__(self, label, profile, region):
        self.label = label
        self.session = boto3.Session(profile_name=profile, region_name=region)
        identity = self.session.client("sts").get_caller_identity()
        self.id = identity["Account"]
        self.partition = identity["Arn"].split(":")[1]
        self.region = region

    def client(self, name):
        return self.session.client(name)

    def bucket(self, suffix):
        return f"orch-live-test-{self.id}-{suffix}"

    def import_finding(self, name, generator, title, resource, types=None, severity="HIGH"):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        finding_id = f"live-test/{RUN['run_id']}/{name}"
        response = self.client("securityhub").batch_import_findings(Findings=[{
            "SchemaVersion": "2018-10-08",
            "Id": finding_id,
            "ProductArn": f"arn:{self.partition}:securityhub:{self.region}:{self.id}:product/{self.id}/default",
            "GeneratorId": generator,
            "AwsAccountId": self.id,
            "Types": types or ["Software and Configuration Checks/Industry and Regulatory Standards"],
            "CreatedAt": now,
            "UpdatedAt": now,
            "Severity": {"Label": severity},
            "Title": title,
            "Description": "Synthetic finding from live_test.py about a real throwaway resource.",
            "Resources": [resource],
        }])
        assert response["FailedCount"] == 0, response
        RUN["findings"][name] = {"id": finding_id, "account": self.label}
        print(f"imported {name} in {self.label}")


def s3_resource(account, bucket):
    return {"Type": "AwsS3Bucket", "Id": f"arn:{account.partition}:s3:::{bucket}", "Region": account.region}


def setup(hub, a, b, _outside):
    RUN["run_id"] = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    for account, suffixes in ((hub, ["hub"]), (a, ["member", "denylisted"])):
        s3 = account.client("s3")
        for suffix in suffixes:
            name = account.bucket(suffix)
            extra = {} if account.region == "us-east-1" else {
                "CreateBucketConfiguration": {"LocationConstraint": account.region}}
            s3.create_bucket(Bucket=name, **extra)
            s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=BPA_OFF)
            if suffix == "denylisted":
                s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "do-not-remediate", "Value": "true"}]})
            print(f"created {name} with Block Public Access off")

    a.client("iam").create_role(
        RoleName=VICTIM_ROLE,
        Description="live_test.py target for RevokeRoleSessions. No permissions.",
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}),
    )
    print(f"created role {VICTIM_ROLE} in {a.label}")

    ec2 = b.client("ec2")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    group = ec2.create_security_group(
        GroupName=f"live-test-{RUN['run_id']}", VpcId=vpc,
        Description="live_test.py target. Attached to nothing.")["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=group, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "IpRanges": [{"CidrIp": cidr}]}
        for port, cidr in OPEN_RULES])
    RUN["security_group"] = group
    print(f"created {group} in {b.label} with {OPEN_RULES}")


def auto(hub, a, b, outside):
    s3_title = "S3 general purpose buckets should block public access"
    hub.import_finding("s3-hub", "security-control/S3.8", s3_title, s3_resource(hub, hub.bucket("hub")))
    a.import_finding("s3-member", "security-control/S3.8", s3_title, s3_resource(a, a.bucket("member")))
    a.import_finding("s3-denylisted", "security-control/S3.8", s3_title, s3_resource(a, a.bucket("denylisted")))
    b.import_finding(
        "sg-member", "security-control/EC2.13",
        "Security groups should not allow ingress from 0.0.0.0/0 or ::/0 to port 22",
        {"Type": "AwsEc2SecurityGroup", "Region": b.region,
         "Id": f"arn:{b.partition}:ec2:{b.region}:{b.id}:security-group/{RUN['security_group']}"})
    if outside:
        outside.import_finding("not-onboarded", "security-control/S3.8", s3_title,
                               s3_resource(outside, "live-test-no-such-bucket"))

    guardduty = b.client("guardduty")
    detector = guardduty.list_detectors()["DetectorIds"][0]
    guardduty.create_sample_findings(DetectorId=detector, FindingTypes=["Policy:IAMUser/RootCredentialUsage"])
    RUN["guardduty_sample_after"] = datetime.now(timezone.utc).isoformat()
    print(f"asked GuardDuty in {b.label} for a real sample finding")


def approval(_hub, a, _b, _outside):
    a.import_finding(
        "role-sessions", "live-test/guardduty-shaped",
        "Credentials for an instance role were used from an external IP address",
        {"Type": "AwsIamAccessKey", "Id": "AWS::IAM::AccessKey:ASIALIVETESTEXAMPLE", "Region": a.region,
         "Details": {"AwsIamAccessKey": {"PrincipalType": "AssumedRole", "PrincipalName": VICTIM_ROLE}}},
        types=["Effects/Data Exfiltration/UnauthorizedAccess:IAMUser-InstanceCredentialExfiltration.OutsideAWS"])
    print("An approval email is on its way. Click Approve, then run collect.")


def breaker(_hub, a, _b, _outside):
    # Limit 2 per hour: two pass, the rest are blocked, and at three times
    # the limit the breaker trips, which blocks the last one on its own.
    for n in range(1, 8):
        a.import_finding(f"rate-{n}", "live-test/rate-limit", f"Rate limit test {n}",
                         {"Type": "Other", "Id": f"live-test-rate-{n}"}, severity="LOW")
        time.sleep(20)  # one at a time, so the ledger order matches


def ledger_entries(hub, table, finding_id, wait_seconds):
    dynamodb = hub.session.resource("dynamodb").Table(table)
    deadline = time.time() + wait_seconds
    while True:
        items = dynamodb.query(
            KeyConditionExpression="finding_id = :f", ExpressionAttributeValues={":f": finding_id})["Items"]
        if items or time.time() > deadline:
            return items
        time.sleep(10)


def finding_results(hub, accounts, table, detail="guardrail_reason"):
    """Ledger entries and SSM automation for every finding this run sent."""
    results = {}
    for name, finding in RUN["findings"].items():
        owner = accounts[finding["account"]]
        entries = ledger_entries(hub, table, finding["id"], wait_seconds=180)
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
        print(name, [(e["policy_id"], e["outcome"], e.get(detail)) for e in entries] or "NO LEDGER ENTRY")
    return results


def export_evidence(hub, bucket):
    export = hub.client("lambda").invoke(FunctionName="remediation-orchestrator-export-evidence")
    exported = json.loads(export["Payload"].read())
    s3 = hub.client("s3")
    documents = {}
    for obj in s3.list_objects_v2(Bucket=bucket, Prefix="remediation-orchestrator/").get("Contents", []):
        body = json.loads(s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read())
        documents[obj["Key"]] = {k: body[k] for k in ("account", "status", "summary", "controls", "data", "sha256")}
    return {"invocation": exported, "documents": documents}


def write_evidence(path, evidence, accounts):
    text = json.dumps(evidence, indent=2, default=str)
    for account in accounts.values():  # account IDs never go in the repo
        text = text.replace(account.id, f"<{account.label}>")
    assert not re.search(r"\b\d{12}\b", text), "unmasked account ID in evidence"
    path.write_text(text, encoding="utf-8")
    print(f"wrote {path}")


def resolve_findings(accounts, updated_by):
    for finding in RUN.get("findings", {}).values():
        if finding.get("real"):
            continue
        owner = accounts[finding["account"]]
        owner.client("securityhub").batch_update_findings(
            FindingIdentifiers=[{
                "Id": finding["id"],
                "ProductArn": f"arn:{owner.partition}:securityhub:{owner.region}:{owner.id}:product/{owner.id}/default"}],
            Workflow={"Status": "RESOLVED"}, Note={"Text": "live test cleanup", "UpdatedBy": updated_by})


def collect(hub, a, b, outside):
    accounts = {x.label: x for x in (hub, a, b, outside) if x}
    outputs = json.loads(subprocess.run(
        ["terraform", "output", "-json", "orchestrator"], check=True, capture_output=True, text=True,
        cwd=Path(__file__).parent).stdout)

    sample = b.client("securityhub").get_findings(Filters={
        "Type": [{"Value": "TTPs/Policy:IAMUser-RootCredentialUsage", "Comparison": "EQUALS"}],
        "AwsAccountId": [{"Value": b.id, "Comparison": "EQUALS"}],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]})["Findings"]
    if sample:
        RUN["findings"]["guardduty-sample"] = {"id": sample[0]["Id"], "account": b.label, "real": True}

    results = finding_results(hub, accounts, outputs["ledger_table"])

    def block_public_access(account, suffix):
        return account.client("s3").get_public_access_block(
            Bucket=account.bucket(suffix))["PublicAccessBlockConfiguration"]

    group = b.client("ec2").describe_security_groups(GroupIds=[RUN["security_group"]])["SecurityGroups"][0]
    iam = a.client("iam")
    victim_policies = iam.list_role_policies(RoleName=VICTIM_ROLE)["PolicyNames"]
    state_after = {
        "hub_bucket_block_public_access": block_public_access(hub, "hub"),
        "member_bucket_block_public_access": block_public_access(a, "member"),
        "denylisted_bucket_block_public_access": block_public_access(a, "denylisted"),
        "security_group_rules_before": [f"{port} from {cidr}" for port, cidr in OPEN_RULES],
        "security_group_rules_after": sorted(
            f"{p['FromPort']} from {r['CidrIp']}" for p in group["IpPermissions"] for r in p["IpRanges"]),
        "victim_role_inline_policies": victim_policies,
        "victim_role_revoke_policy": iam.get_role_policy(
            RoleName=VICTIM_ROLE, PolicyName=victim_policies[0])["PolicyDocument"] if victim_policies else None,
        "circuit_breaker": hub.client("ssm").get_parameter(
            Name=outputs["circuit_breaker_param"], WithDecryption=True)["Parameter"]["Value"],
    }

    evidence = {
        "run_id": RUN["run_id"],
        "accounts": {x.label: x.id for x in accounts.values()},
        "findings": results,
        "resource_state_after": state_after,
        "evidence_export": export_evidence(hub, outputs["evidence_bucket"]),
    }
    write_evidence(EVIDENCE, evidence, accounts)


def cleanup(hub, a, b, outside):
    accounts = {x.label: x for x in (hub, a, b, outside) if x}
    resolve_findings(accounts, "live_test.py")
    for account, suffixes in ((hub, ["hub"]), (a, ["member", "denylisted"])):
        for suffix in suffixes:
            account.client("s3").delete_bucket(Bucket=account.bucket(suffix))
    iam = a.client("iam")
    for policy in iam.list_role_policies(RoleName=VICTIM_ROLE)["PolicyNames"]:
        iam.delete_role_policy(RoleName=VICTIM_ROLE, PolicyName=policy)
    iam.delete_role(RoleName=VICTIM_ROLE)
    b.client("ec2").delete_security_group(GroupId=RUN["security_group"])
    print("deleted the test buckets, role and security group; resolved the imported findings")
    print("If the circuit breaker is still 'true', reset it or run terraform destroy.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("stage", choices=["setup", "auto", "approval", "breaker", "collect", "cleanup"])
    parser.add_argument("--hub", required=True, help="profile for the hub account")
    parser.add_argument("--member-a", required=True, help="profile for the first member account")
    parser.add_argument("--member-b", required=True, help="profile for the second member account")
    parser.add_argument("--outside", help="profile for an account that is not onboarded")
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()

    RUN = json.loads(STATE.read_text()) if STATE.exists() else {"findings": {}}
    stage_accounts = [
        Account("hub", args.hub, args.region),
        Account("member-a", args.member_a, args.region),
        Account("member-b", args.member_b, args.region),
        Account("outside", args.outside, args.region) if args.outside else None,
    ]
    try:
        globals()[args.stage](*stage_accounts)
    finally:
        STATE.write_text(json.dumps(RUN, indent=2))
