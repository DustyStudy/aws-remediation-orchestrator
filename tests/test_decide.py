from unittest.mock import MagicMock, patch

import pytest
from botocore.credentials import Credentials


@pytest.mark.parametrize("url", [
    "http://abc.execute-api.us-east-1.amazonaws.com/decision",
    "https://abc.execute-api.us-east-1.amazonaws.com.evil.example/decision",
    "https://example.com/decision", "https://abc.execute-api.us-east-1.amazonaws.com/other",
    "https://user:password@abc.execute-api.us-east-1.amazonaws.com/decision",
])
def test_refuses_to_send_credentials_to_unexpected_hosts(load_module, url):
    module = load_module("scripts/decide.py")
    with pytest.raises(ValueError):
        module.submit(url, Credentials("test", "secret", "session"))


def test_submission_uses_signed_post_and_session_credentials(load_module):
    module = load_module("scripts/decide.py")
    connection = MagicMock()
    connection.getresponse.return_value.status = 200
    connection.getresponse.return_value.read.return_value = b"Decision delivered: approve."
    with patch.object(module.http.client, "HTTPSConnection", return_value=connection):
        status, body = module.submit(
            "https://abc.execute-api.us-gov-west-1.amazonaws.com/decision?approval_id=a&decision=approve&sig=s",
            Credentials("test", "secret", "session"),
        )
    args, kwargs = connection.request.call_args
    assert args[0] == "POST"
    assert kwargs["headers"]["X-Amz-Security-Token"] == "session"
    assert "us-gov-west-1/execute-api/aws4_request" in kwargs["headers"]["Authorization"]
    assert status == 200 and "approve" in body
