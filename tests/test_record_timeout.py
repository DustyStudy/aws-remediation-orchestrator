import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

STATE_MACHINE = "arn:aws:states:us-east-1:123456789012:stateMachine:remediation-orchestrator"
EXECUTION = "arn:aws:states:us-east-1:123456789012:execution:remediation-orchestrator:run-1"
START_MS = 1795543488476  # 2026-11-24T18:04:48.476Z
STOP_MS = START_MS + 120_000


def finding(identifier):
    return {
        "Id": identifier, "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/aws/guardduty",
        "Title": "Role credentials used from outside AWS", "GeneratorId": "guardduty",
        "AwsAccountId": "123456789012",
    }


def security_hub_event(*findings):
    return {"id": "event-1", "account": "123456789012", "region": "us-east-1",
            "detail": {"findings": list(findings)}}


def status_event(execution_input, *, status="TIMED_OUT", state_machine=STATE_MACHINE, include_input=True):
    detail = {
        "executionArn": EXECUTION, "stateMachineArn": state_machine, "status": status,
        "startDate": START_MS, "stopDate": STOP_MS,
    }
    if include_input:
        detail["input"] = json.dumps(execution_input)
    return {"source": "aws.states", "detail-type": "Step Functions Execution Status Change", "detail": detail}


@pytest.fixture
def module(load_module):
    loaded = load_module(
        "terraform/lambda/record_timeout/handler.py",
        LEDGER_TABLE_NAME="ledger", STATE_MACHINE_ARN=STATE_MACHINE,
    )
    loaded._dynamodb = MagicMock()
    loaded._sfn = MagicMock()
    return loaded


def table(module):
    return module._dynamodb.Table.return_value


def test_records_each_unrecorded_finding_as_timed_out(module):
    table(module).query.return_value = {"Items": []}
    result = module.handler(status_event(security_hub_event(finding("one"), finding("two"))), None)

    assert result["recorded"] == ["one", "two"]
    items = [call.kwargs["Item"] for call in table(module).put_item.call_args_list]
    assert [item["outcome"] for item in items] == ["timed_out", "timed_out"]
    first = items[0]
    assert first["execution_ts"] == "2026-11-24T18:06:48.476Z"
    assert first["execution_status"] == "TIMED_OUT"
    assert first["guardrail_reason"] == "execution_timed_out"
    assert first["decided_by"] == "system"
    assert first["workflow_execution_arn"] == EXECUTION
    assert first["account_id"] == "123456789012"
    for call in table(module).put_item.call_args_list:
        assert call.kwargs["ConditionExpression"] == "attribute_not_exists(finding_id)"


def test_findings_the_execution_already_recorded_are_left_alone(module):
    table(module).query.side_effect = [{"Items": [{"finding_id": "done"}]}, {"Items": []}]
    result = module.handler(status_event(security_hub_event(finding("done"), finding("waiting"))), None)

    assert result["already_recorded"] == ["done"]
    assert result["recorded"] == ["waiting"]
    assert table(module).put_item.call_count == 1


def test_the_lookup_covers_the_execution_lifetime(module):
    table(module).query.return_value = {"Items": []}
    module.handler(status_event(security_hub_event(finding("one"))), None)

    condition = table(module).query.call_args.kwargs["KeyConditionExpression"]
    values = condition.get_expression()["values"]
    key, between = values
    assert key.get_expression()["values"][1] == "one"
    _, start, stop = between.get_expression()["values"]
    # Step Functions EnteredTime values from the start to the stop must fall inside.
    assert start <= "2026-11-24T18:04:48.476Z" <= "2026-11-24T18:06:48.476Z" <= stop
    assert start > "2026-11-24T18:04:46" and stop < "2026-11-24T18:06:50"


def test_a_redelivered_event_writes_nothing_twice(module):
    table(module).query.return_value = {"Items": []}
    table(module).put_item.side_effect = ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException", "Message": "exists"}}, "PutItem")
    result = module.handler(status_event(security_hub_event(finding("one"))), None)

    assert result["recorded"] == []
    assert result["already_recorded"] == ["one"]


def test_other_write_errors_are_raised_for_retry(module):
    table(module).query.return_value = {"Items": []}
    table(module).put_item.side_effect = ClientError(
        {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "slow down"}}, "PutItem")
    with pytest.raises(ClientError):
        module.handler(status_event(security_hub_event(finding("one"))), None)


def test_rejected_findings_get_the_same_id_as_the_normalizer(module, load_module):
    table(module).query.return_value = {"Items": []}
    event = security_hub_event({"bad": True}, finding("valid"))
    normalizer = load_module("terraform/lambda/normalize_finding/handler.py")
    expected = [item["finding"]["finding_id"] for item in normalizer.handler(event, None)["findings"]]

    result = module.handler(status_event(event), None)
    assert result["recorded"] == expected
    assert expected[0].startswith("rejected:event-1:")


def test_input_left_out_of_the_event_is_read_from_the_execution(module):
    table(module).query.return_value = {"Items": []}
    module._sfn.describe_execution.return_value = {"input": json.dumps(security_hub_event(finding("big")))}
    result = module.handler(status_event(None, include_input=False), None)

    module._sfn.describe_execution.assert_called_once_with(executionArn=EXECUTION)
    assert result["recorded"] == ["big"]


@pytest.mark.parametrize("kwargs", [
    {"status": "SUCCEEDED"},
    {"state_machine": "arn:aws:states:us-east-1:123456789012:stateMachine:another"},
])
def test_other_events_are_ignored(module, kwargs):
    result = module.handler(status_event(security_hub_event(finding("one")), **kwargs), None)
    assert result["ignored"] is True
    table(module).put_item.assert_not_called()
