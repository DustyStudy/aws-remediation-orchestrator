"""Submit an approval with credentials from an existing AWS/Identity Center profile."""
from __future__ import annotations

import argparse
import getpass
import http.client
import re
from urllib.parse import parse_qs, urlsplit

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest


def submit(url, credentials):
    parsed = urlsplit(url)
    host = re.fullmatch(
        r"[a-z0-9]+\.execute-api\.([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?", parsed.netloc
    )
    if parsed.scheme != "https" or not host or parsed.path != "/decision" or parsed.fragment:
        raise ValueError("Expected an HTTPS API Gateway /decision link from this deployment.")
    params = parse_qs(parsed.query)
    if set(params) != {"approval_id", "decision", "sig"} or any(len(v) != 1 for v in params.values()):
        raise ValueError("The approval link must contain one approval_id, decision and sig.")
    if params["decision"][0] not in ("approve", "deny"):
        raise ValueError("Invalid decision in approval link.")
    request = AWSRequest(method="POST", url=url, data=b"")
    SigV4Auth(credentials, "execute-api", host[1]).add_auth(request)
    connection = http.client.HTTPSConnection(parsed.netloc, timeout=30)
    try:
        # http.client never follows redirects, so credentials stay on this host.
        connection.request("POST", parsed.path + "?" + parsed.query, body=b"", headers=dict(request.headers))
        response = connection.getresponse()
        return response.status, response.read().decode("utf-8")
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", help="Existing AWS CLI / Identity Center profile")
    args = parser.parse_args()
    # Keep signed links out of process arguments and shell history.
    url = getpass.getpass("Paste the signed decision link: ").strip()
    decision = parse_qs(urlsplit(url).query).get("decision", [""])[0]
    if decision not in ("approve", "deny") or input(f"Type {decision} to submit: ") != decision:
        raise SystemExit("No decision submitted.")
    credentials = boto3.Session(profile_name=args.profile).get_credentials()
    if credentials is None:
        raise SystemExit("Sign in to your approver profile first (aws sso login --profile ...).")
    status, body = submit(url, credentials.get_frozen_credentials())
    print(body)
    raise SystemExit(0 if status == 200 else 1)


if __name__ == "__main__":
    main()
