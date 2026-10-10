"""Live test of the IAM-authenticated approval flow, delivery recovery and batches.

Runs against the same examples/org-mode deployment as live_test.py and
follows one finding from Security Hub to the exported evidence:

* an approval request whose GET link only displays it
* an Approve submitted while the callback cannot reach Step Functions
  (HTTP 503), the opposite decision refused while that one is reserved
  (409), and the same Approve delivered from a new process once the
  fault is removed (200)
* RevokeRoleSessions in member-a, the ledger entry and the evidence export
* one execution holding three findings, one of them malformed

    python live_test_approval.py setup   --hub P --member-a P --member-b P
    python live_test_approval.py send    ...   # the finding that needs approval
    python live_test_approval.py decide  ...   # review, then fail on purpose
    python live_test_approval.py resume  ...   # the same Approve, until it is delivered
    python live_test_approval.py batch   ...   # three findings in one execution
    python live_test_approval.py collect ...   # writes the evidence file
    python live_test_approval.py cleanup ...

The fault is an inline policy on the callback function's role that denies
states:SendTaskSuccess. decide adds it, removes it, and removes it again
on the way out if anything fails in between.

A decision can only be retried by the identity that reserved it, and the
role session name is part of that identity. A profile that assumes a role
gets a new session name per process unless it sets role_session_name, so
resume assumes the role itself under the name that made the reservation.
Set approval_timeout_seconds to at least 600: a removed IAM deny can keep
applying for several minutes, and resume has to finish inside the timeout.

Security Hub has sent one finding per event in every run, so batch starts
the execution itself, with an event shaped like the one EventBridge
delivers. The two well-formed findings match the dry-run policy.
"""
import argparse
import json
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.credentials import ReadOnlyCredentials

import live_test
import live_test_playbooks
from live_test import (
    VICTIM_ROLE,
    Account,
    export_evidence,
    finding_results,
    ledger_entries,
    resolve_findings,
    write_evidence,
)
from live_test_playbooks import approval_links, outputs, role_finding, subscribe_queue

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts"))
import decide as decide_script

STATE = Path(__file__).with_name(".live-test-approval-state.json")
EVIDENCE = Path(__file__).with_name("live-test-approval-evidence.json")
FINDING = "approval-recovery"
CALLBACK_ROLE = "remediation-orchestrator-approval-callback-role"
FAULT_POLICY = "live-test-deny-send-task-success"
PENDING_TABLE = "remediation-orchestrator-pending-approvals"
PROPAGATION_SECONDS = 30  # IAM is eventually consistent


def now():
    return datetime.now(timezone.utc).isoformat()


def setup(hub, a, _b):
    RUN["run_id"] = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    a.client("iam").create_role(
        RoleName=VICTIM_ROLE,
        Description="live_test_approval.py target for RevokeRoleSessions. No permissions.",
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}),
    )
    print(f"created role {VICTIM_ROLE} in {a.label}")
    subscribe_queue(hub)


def send(_hub, a, _b):
    RUN["imported_at"] = now()
    role_finding(a, FINDING)
    print("Run decide next, within approval_timeout_seconds.")


def pending_item(hub, approval_id):
    """The request as DynamoDB holds it, without the task token."""
    item = hub.session.resource("dynamodb").Table(PENDING_TABLE).get_item(
        Key={"approval_id": approval_id}, ConsistentRead=True)["Item"]
    return {k: item.get(k) for k in ("consumed", "decision", "decided_by")}


def find_execution(hub, state_machine, finding_id):
    sfn = hub.client("stepfunctions")
    for execution in sfn.list_executions(stateMachineArn=state_machine, statusFilter="RUNNING")["executions"]:
        if finding_id in sfn.describe_execution(executionArn=execution["executionArn"])["input"]:
            return execution["executionArn"]
    raise SystemExit("no running execution holds the finding")


def record(hub, step, status=None, body=None):
    """One request and what it left behind, checked against DynamoDB and Step Functions."""
    approval = RUN["approval"]
    approval["steps"].append({
        "step": step, "at": now(), "http_status": status, "response": body,
        "pending_request": pending_item(hub, approval["approval_id"]),
        "execution_status": hub.client("stepfunctions").describe_execution(
            executionArn=approval["execution_arn"])["status"],
    })
    last = approval["steps"][-1]
    print(step, status, last["pending_request"], last["execution_status"])
    return status


def decide(hub, _a, _b):
    links = approval_links(hub, FINDING)
    RUN["approval"] = {
        "approval_id": re.search(r"approval_id=([0-9a-f]+)", links["approve"]).group(1),
        "execution_arn": find_execution(hub, outputs()["state_machine_arn"], RUN["findings"][FINDING]["id"]),
        "requested_at": links["requested_at"], "steps": [],
    }
    iam = hub.client("iam")
    credentials = hub.session.get_credentials().get_frozen_credentials()
    with urllib.request.urlopen(links["approve"], timeout=30) as response:
        record(hub, "GET the Approve link", response.status, response.read().decode())

    try:
        iam.put_role_policy(RoleName=CALLBACK_ROLE, PolicyName=FAULT_POLICY, PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "states:SendTaskSuccess", "Resource": "*"}]}))
        time.sleep(PROPAGATION_SECONDS)
        if record(hub, "POST Approve while the callback cannot reach Step Functions",
                  *decide_script.submit(links["approve"], credentials)) != 503:
            raise SystemExit("the fault did not take effect; nothing to recover from")
        record(hub, "POST Deny while Approve is reserved", *decide_script.submit(links["deny"], credentials))
    finally:
        iam.delete_role_policy(RoleName=CALLBACK_ROLE, PolicyName=FAULT_POLICY)
    print("The fault is removed. Run resume next.")


def resume(hub, _a, _b):
    """Retry the reserved decision from this new process, as the identity that reserved it."""
    links = approval_links(hub, FINDING)  # unacknowledged, so the queue hands the request out again
    actor = pending_item(hub, RUN["approval"]["approval_id"])["decided_by"]
    profile = hub.session._session.get_scoped_config()
    if "role_arn" in profile:
        # A profile that assumes a role would get a new session name here.
        credentials = boto3.Session(profile_name=profile["source_profile"]).client("sts").assume_role(
            RoleArn=profile["role_arn"], RoleSessionName=actor.rsplit("/", 1)[1])["Credentials"]
        credentials = ReadOnlyCredentials(
            credentials["AccessKeyId"], credentials["SecretAccessKey"], credentials["SessionToken"])
    else:
        credentials = hub.session.get_credentials().get_frozen_credentials()

    # The removed deny kept applying for over four minutes in the recorded run.
    deadline = time.time() + 420
    while record(hub, "POST the same Approve from a new process with the reserving session name",
                 *decide_script.submit(links["approve"], credentials)) != 200:
        if time.time() > deadline:
            raise SystemExit("the approval was not delivered within seven minutes of removing the fault")
        time.sleep(15)


def batch(hub, a, _b):
    def finding(n):
        return {
            "SchemaVersion": "2018-10-08", "Id": f"live-test/{RUN['run_id']}/batch-{n}",
            "ProductArn": f"arn:{a.partition}:securityhub:{a.region}:{a.id}:product/{a.id}/default",
            "GeneratorId": "live-test/rate-limit", "AwsAccountId": a.id, "Title": f"Batch test {n}",
            "Types": ["Software and Configuration Checks"], "Severity": {"Label": "LOW"},
            "RecordState": "ACTIVE", "Workflow": {"Status": "NEW"},
            "Resources": [{"Type": "Other", "Id": f"live-test-batch-{n}"}],
        }

    event_id = f"live-test-{RUN['run_id']}"
    event = {
        "id": event_id, "source": "aws.securityhub", "detail-type": "Security Hub Findings - Imported",
        "account": hub.id, "region": hub.region,
        "detail": {"findings": [finding(1), finding(2), {"Id": 3}]},
    }
    RUN["batch"] = {
        "execution_arn": hub.client("stepfunctions").start_execution(
            stateMachineArn=outputs()["state_machine_arn"], name=event_id, input=json.dumps(event))["executionArn"],
        "finding_ids": [finding(1)["Id"], finding(2)["Id"], f"rejected:{event_id}:2"],
    }
    print("started one execution with two findings and one malformed entry")


def timeline(hub, execution_arn):
    """When the execution entered each state, from Step Functions' own history."""
    sfn = hub.client("stepfunctions")
    execution = sfn.describe_execution(executionArn=execution_arn)
    entered = [
        {"at": event["timestamp"], "state": event["stateEnteredEventDetails"]["name"]}
        for page in sfn.get_paginator("get_execution_history").paginate(executionArn=execution_arn)
        for event in page["events"] if "stateEnteredEventDetails" in event]
    return {"status": execution["status"], "started": execution["startDate"],
            "stopped": execution.get("stopDate"), "states_entered": entered}


def collect(hub, a, b):
    accounts = {x.label: x for x in (hub, a, b)}
    out = outputs()
    results = finding_results(hub, accounts, out["ledger_table"], detail="decided_by")

    approval = dict(RUN["approval"], imported_at=RUN["imported_at"])
    del approval["approval_id"]
    approval["execution"] = timeline(hub, approval.pop("execution_arn"))
    batch_run = {
        "execution": timeline(hub, RUN["batch"]["execution_arn"]),
        "ledger": {finding_id: ledger_entries(hub, out["ledger_table"], finding_id, wait_seconds=60)
                   for finding_id in RUN["batch"]["finding_ids"]},
    }
    for finding_id, entries in batch_run["ledger"].items():
        print(finding_id, [(e["outcome"], e.get("guardrail_reason")) for e in entries] or "NO LEDGER ENTRY")

    iam = a.client("iam")
    policies = iam.list_role_policies(RoleName=VICTIM_ROLE)["PolicyNames"]
    cwd = Path(__file__).parent
    evidence = {
        "run_id": RUN["run_id"],
        "revision": subprocess.run(
            ["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True, cwd=cwd).stdout.strip(),
        "deployed_resources": len(subprocess.run(
            ["terraform", "state", "list"], check=True, capture_output=True, text=True, cwd=cwd).stdout.split()),
        "accounts": {x.label: x.id for x in accounts.values()},
        "findings": results,
        "approval": approval,
        "batch": batch_run,
        "resource_state_after": {
            "victim_role_inline_policies": policies,
            "victim_role_revoke_policy": iam.get_role_policy(
                RoleName=VICTIM_ROLE, PolicyName=policies[0])["PolicyDocument"] if policies else None,
            "callback_role_inline_policies": hub.client("iam").list_role_policies(
                RoleName=CALLBACK_ROLE)["PolicyNames"],
            "workflow_alarms": {
                alarm["AlarmName"]: alarm["StateValue"]
                for alarm in hub.client("cloudwatch").describe_alarms(
                    AlarmNamePrefix="remediation-orchestrator-Executions")["MetricAlarms"]},
        },
        "evidence_export": export_evidence(hub, out["evidence_bucket"]),
    }
    write_evidence(EVIDENCE, evidence, accounts)
    # The role session name can be a person's sign-in name.
    EVIDENCE.write_text(re.sub(r"(assumed-role/[^/\"]+/)[^\"\\]+", r"\1<session>", EVIDENCE.read_text("utf-8")), "utf-8")


def cleanup(hub, a, b):
    resolve_findings({x.label: x for x in (hub, a, b)}, "live_test_approval.py")
    iam = a.client("iam")
    for policy in iam.list_role_policies(RoleName=VICTIM_ROLE)["PolicyNames"]:
        iam.delete_role_policy(RoleName=VICTIM_ROLE, PolicyName=policy)
    iam.delete_role(RoleName=VICTIM_ROLE)
    if FAULT_POLICY in hub.client("iam").list_role_policies(RoleName=CALLBACK_ROLE)["PolicyNames"]:
        hub.client("iam").delete_role_policy(RoleName=CALLBACK_ROLE, PolicyName=FAULT_POLICY)
    hub.client("sns").unsubscribe(SubscriptionArn=RUN["subscription"])
    hub.client("sqs").delete_queue(QueueUrl=RUN["queue_url"])
    print("deleted the role and queue; resolved the finding")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("stage", choices=["setup", "send", "decide", "resume", "batch", "collect", "cleanup"])
    parser.add_argument("--hub", required=True, help="profile for the hub account")
    parser.add_argument("--member-a", required=True, help="profile for the first member account")
    parser.add_argument("--member-b", required=True, help="profile for the second member account")
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()

    RUN = json.loads(STATE.read_text()) if STATE.exists() else {"findings": {}}
    live_test.RUN = live_test_playbooks.RUN = RUN  # the shared helpers record into it
    try:
        globals()[args.stage](
            Account("hub", args.hub, args.region),
            Account("member-a", args.member_a, args.region),
            Account("member-b", args.member_b, args.region),
        )
    finally:
        STATE.write_text(json.dumps(RUN, indent=2))
