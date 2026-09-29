"""
Receives Wiz webhook deliveries (Settings -> Integrations -> Webhook, fired
by a Policies -> Automation Rule) via API Gateway, imports each one into
Security Hub as an ASFF finding so it enters the remediation orchestrator
through the same EventBridge rule as every other finding, and publishes an
SNS notification.

This module is deliberately schema-tolerant rather than schema-assuming.
Wiz's outbound webhook JSON shape isn't something this repo can verify
against a live tenant, and it can change between Wiz product versions.
Hardcoding field paths that turn out wrong would fail silently - worse
than not having this tool at all. Instead:

  - The raw payload (truncated) is always included in the SNS message.
  - Which fields to treat as "severity" / "title" / "resource" / "id" are
    dot-notation paths read from environment variables, not hardcoded.
  - Until you set those paths to match your real payload, everything
    still gets forwarded with an "UNKNOWN" placeholder where a field
    couldn't be resolved - fails open on notification, not silent.

Auth model: Wiz's basic Webhook integration (as of this writing) only
lets you configure a destination URL, not custom headers or payload
signing. So instead of verifying a header, this Lambda expects a long
random secret token as the last path segment of the webhook URL itself
(e.g. https://.../wiz-webhook/<secret>) - the same "unguessable URL"
pattern most webhook-only integrations rely on. The secret is generated
by the Terraform deploy and stored in Secrets Manager;
see the module README for how to retrieve it and build the full URL to
paste into Wiz.

Env vars:
  SNS_TOPIC_ARN              - where to publish the bridged notification
  WEBHOOK_SECRET_ARN         - Secrets Manager secret holding the token
                                that must match the URL path segment
  MIN_SEVERITY               - lowest severity to notify on: CRITICAL,
                                HIGH, MEDIUM, LOW, or INFORMATIONAL
                                (default HIGH). A finding whose severity
                                can't be resolved is always notified,
                                regardless of this setting - fail open.
  SEVERITY_FIELD_PATH        - dot-notation path to the severity field
                                in the Wiz payload (default "severity")
  TITLE_FIELD_PATH           - dot-notation path to a human-readable
                                title/rule-name field (default "title")
  RESOURCE_FIELD_PATH        - dot-notation path to a resource
                                object/identifier field (default
                                "primaryResource" - an object in Wiz's
                                schema, rendered as JSON in the report
                                since its internal shape isn't assumed)
  RESOURCE_ID_FIELD_PATH     - dot-notation path to a string that names
                                the resource (ideally its AWS ARN), used
                                as the imported finding's Resources[0].Id.
                                Empty (the default) or unresolved imports
                                the finding with a placeholder id, which
                                the orchestrator can match and log but
                                no playbook can act on.
  ID_FIELD_PATH              - dot-notation path to Wiz's own id for the
                                issue (default "id"). Repeat deliveries
                                with the same id update one Security Hub
                                finding instead of creating another. If
                                unresolved, a hash of the payload is used.
  ACCOUNT_ID                 - this account; the imported finding's
                                AwsAccountId and ProductArn owner
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

secretsmanager = boto3.client("secretsmanager")
sns = boto3.client("sns")
securityhub = boto3.client("securityhub")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
WEBHOOK_SECRET_ARN = os.environ.get("WEBHOOK_SECRET_ARN")
MIN_SEVERITY = os.environ.get("MIN_SEVERITY", "HIGH").upper()
SEVERITY_FIELD_PATH = os.environ.get("SEVERITY_FIELD_PATH", "severity")
TITLE_FIELD_PATH = os.environ.get("TITLE_FIELD_PATH", "title")
RESOURCE_FIELD_PATH = os.environ.get("RESOURCE_FIELD_PATH", "primaryResource")
RESOURCE_ID_FIELD_PATH = os.environ.get("RESOURCE_ID_FIELD_PATH", "")
ID_FIELD_PATH = os.environ.get("ID_FIELD_PATH", "id")
ACCOUNT_ID = os.environ.get("ACCOUNT_ID", "")
REGION = os.environ.get("AWS_REGION", "")
PARTITION = os.environ.get("AWS_PARTITION", "aws")

SEVERITY_RANK = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFORMATIONAL": 1,
}

MAX_RAW_PAYLOAD_CHARS = 2000

# SNS only accepts printable ASCII in a Subject (no newlines, control or
# non-ASCII characters). The title comes from an external payload, so
# collapse anything else - otherwise one odd title would make SNS reject
# the publish and the notification would be silently dropped.
_NON_SUBJECT_CHARS = re.compile(r"[^\x20-\x7e]+")

# Cached across warm Lambda invocations to avoid a Secrets Manager call
# on every webhook delivery. The cache expires after a short TTL so a
# rotated secret (e.g. after a suspected URL leak) stops being accepted
# within minutes, not whenever the execution environment happens to be
# recycled.
SECRET_CACHE_TTL_SECONDS = int(os.environ.get("SECRET_CACHE_TTL_SECONDS", "300"))
_cached_secret = None
_cached_secret_at = 0.0


def _get_expected_secret():
    global _cached_secret, _cached_secret_at
    if _cached_secret is not None and time.monotonic() - _cached_secret_at < SECRET_CACHE_TTL_SECONDS:
        return _cached_secret
    try:
        response = secretsmanager.get_secret_value(SecretId=WEBHOOK_SECRET_ARN)
        _cached_secret = response["SecretString"]
        _cached_secret_at = time.monotonic()
        return _cached_secret
    except ClientError:
        logger.exception("Failed to retrieve webhook secret from Secrets Manager")
        # Don't keep honoring a stale secret indefinitely if the refresh fails.
        _cached_secret = None
        return None


def _get_path(obj, path, default=None):
    """Resolve a dot-notation path (e.g. "resource.cloudPlatform.name")
    against a nested dict. Missing keys or a non-dict along the way just
    return the default - never raises."""
    current = obj
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current if current is not None else default


def _http_response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def _import_to_security_hub(payload, raw_body, severity, title, resource_id):
    """Import one Wiz delivery as an ASFF finding. Returns the finding Id,
    or None if the import failed (the SNS notification still goes out)."""
    wiz_id = _get_path(payload, ID_FIELD_PATH) if ID_FIELD_PATH else None
    if not isinstance(wiz_id, str) or not wiz_id:
        wiz_id = hashlib.sha256(raw_body.encode("utf-8")).hexdigest()
    finding_id = f"wiz/{wiz_id}"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": finding_id[:512],
        "ProductArn": f"arn:{PARTITION}:securityhub:{REGION}:{ACCOUNT_ID}:product/{ACCOUNT_ID}/default",
        # The orchestrator's policy registry matches these with a
        # generator_id prefix, e.g. "wiz/" or "wiz/<rule name>".
        "GeneratorId": f"wiz/{title}"[:512],
        "AwsAccountId": ACCOUNT_ID,
        "Types": ["Software and Configuration Checks/Wiz"],
        "CreatedAt": now,
        "UpdatedAt": now,
        "Severity": {"Label": severity if severity in SEVERITY_RANK else "INFORMATIONAL"},
        "Title": title[:256],
        "Description": f"Imported from a Wiz webhook delivery: {title}"[:1024],
        "Resources": [{"Type": "Other", "Id": resource_id[:512]}],
    }
    try:
        response = securityhub.batch_import_findings(Findings=[finding])
    except ClientError:
        logger.exception("Failed to import Wiz finding %s into Security Hub", finding_id)
        return None
    if response.get("FailedCount"):
        logger.error("Security Hub rejected Wiz finding %s: %s", finding_id, response.get("FailedFindings"))
        return None
    return finding_id


def lambda_handler(event, context):
    # API Gateway HTTP API, payload format 2.0
    path_params = event.get("pathParameters") or {}
    provided_secret = path_params.get("secretToken", "")

    expected_secret = _get_expected_secret()
    # Compare as bytes: hmac.compare_digest raises TypeError on non-ASCII
    # str input, which an attacker-controlled path segment could trigger
    # (turning a clean 401 into an unhandled 500).
    if not expected_secret or not hmac.compare_digest(
        provided_secret.encode("utf-8"), expected_secret.encode("utf-8")
    ):
        logger.warning("Rejected webhook delivery with an invalid or missing secret token")
        return _http_response(401, {"message": "unauthorized"})

    raw_body = event.get("body", "") or ""
    if event.get("isBase64Encoded"):
        try:
            raw_body = base64.b64decode(raw_body).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            logger.warning("Webhook body was flagged base64-encoded but could not be decoded")
            return _http_response(200, {"message": "received, but body could not be decoded - not processed"})
    try:
        payload = json.loads(raw_body)
        if not isinstance(payload, dict):
            raise TypeError("Payload was valid JSON but not a JSON object")
    except (TypeError, ValueError):
        logger.exception("Webhook body was not valid JSON")
        # Still 200 - a malformed body isn't something Wiz should retry
        # forever, and we don't want retry storms from a bad delivery.
        return _http_response(200, {"message": "received, but body was not valid JSON - not processed"})

    def _stringify(value):
        # Wiz payloads nest objects/arrays for some fields (e.g. a
        # "primaryResource" object rather than a flat string) - render
        # those as compact JSON instead of Python's str(dict) repr, which
        # uses single quotes and isn't valid JSON, so the report stays
        # copy-pasteable.
        if isinstance(value, (dict, list)):
            return json.dumps(value)
        return str(value)

    severity = _stringify(_get_path(payload, SEVERITY_FIELD_PATH, "UNKNOWN")).upper()
    title = _stringify(_get_path(payload, TITLE_FIELD_PATH, "unknown finding"))
    resource = _stringify(_get_path(payload, RESOURCE_FIELD_PATH, "unknown resource"))

    severity_rank = SEVERITY_RANK.get(severity)
    min_rank = SEVERITY_RANK.get(MIN_SEVERITY, SEVERITY_RANK["HIGH"])

    # Fail open: an unresolved severity (rank is None) is always notified,
    # so a wrong SEVERITY_FIELD_PATH surfaces as noise you'll notice and
    # fix, not as findings silently dropped below a threshold you can't see.
    if severity_rank is not None and severity_rank < min_rank:
        logger.info("Below MIN_SEVERITY (%s < %s) - not notifying: %s", severity, MIN_SEVERITY, title)
        return _http_response(200, {"message": "received, below MIN_SEVERITY threshold"})

    resource_id = _get_path(payload, RESOURCE_ID_FIELD_PATH) if RESOURCE_ID_FIELD_PATH else None
    if not isinstance(resource_id, str) or not resource_id:
        resource_id = "wiz-unresolved-resource"
    imported_id = _import_to_security_hub(payload, raw_body, severity, title, resource_id)

    raw_excerpt = raw_body[:MAX_RAW_PAYLOAD_CHARS]
    if len(raw_body) > MAX_RAW_PAYLOAD_CHARS:
        raw_excerpt += "... (truncated)"

    message_lines = [
        f"Severity: {severity}{'' if severity_rank is not None else ' (unresolved - check SEVERITY_FIELD_PATH)'}",
        f"Title: {title}",
        f"Resource: {resource}",
    ]
    if imported_id:
        message_lines.append(f"Imported into Security Hub as: {imported_id}")
    else:
        message_lines.append("Security Hub import FAILED - see this function's logs")
    message_lines.append("\nRaw payload (use this to tune *_FIELD_PATH env vars if fields above look wrong):")
    message_lines.append(raw_excerpt)

    if SNS_TOPIC_ARN:
        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=_NON_SUBJECT_CHARS.sub(" ", f"Wiz finding: {title}").strip()[:100],
                Message="\n".join(message_lines),
            )
        except ClientError:
            logger.exception("Failed to publish SNS notification")
    else:
        logger.info("SNS_TOPIC_ARN not set, skipping notification")

    return _http_response(200, {"message": "received"})
