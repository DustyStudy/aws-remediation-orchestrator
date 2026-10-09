from unittest.mock import MagicMock

from test_ledger import FINDING


def test_retry_preserves_the_ledger_record_key(load_module):
    module = load_module("terraform/lambda/record_ledger/handler.py", LEDGER_TABLE_NAME="ledger", NOTIFICATION_TOPIC_ARN="topic")
    module._dynamodb = MagicMock()
    module._sns = MagicMock()
    event = {"finding": FINDING, "outcome": "skipped", "timestamp": "2026-10-09T12:00:00Z"}
    first = module.handler(event, None)["ledger_item"]
    second = module.handler(event, None)["ledger_item"]
    assert first["execution_ts"] == second["execution_ts"] == event["timestamp"]
