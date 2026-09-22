# Evidence export

`export_evidence` runs on a schedule (default: daily) and writes one JSON
document per `(account, region)` pair that had ledger activity in the
lookback window, to:

```
s3://<evidence_bucket_name>/remediation-orchestrator/<date>/<account>-<region>.json
```

The document shape matches
[`grc-evidence-automation`](https://github.com/DustyStudy/grc-evidence-automation)'s
own collector output (`schema_version: "1.0"`) - see that repo's
`docs/sample-evidence.json` - specifically so remediation actions taken
here can be ingested into the same compliance evidence pipeline as that
tool's own AWS collectors, rather than living in a format only this repo
understands.

## Example

```json
{
  "account": "123456789012",
  "collected_at": "2026-09-22T06:00:00+00:00",
  "collector": "aws.remediation_orchestrator",
  "controls": {
    "nist_800_53": ["AC-2", "AC-3", "IR-4", "SC-28"]
  },
  "data": {
    "findings_evaluated": 14,
    "remediated": 6,
    "dry_run": 3,
    "blocked_by_guardrail": 1,
    "denied": 1,
    "failed": 0,
    "period_start": "2026-09-21T06:00:00+00:00",
    "period_end": "2026-09-22T06:00:00+00:00"
  },
  "findings": [
    {
      "message": "executed: S3 bucket is publicly accessible",
      "resource": "arn:aws:s3:::example-bucket",
      "severity": "high"
    }
  ],
  "provider": "aws",
  "region": "us-east-1",
  "schema_version": "1.0",
  "status": "pass",
  "summary": "14 finding(s) evaluated between 2026-09-21T06:00:00+00:00 and 2026-09-22T06:00:00+00:00; 6 remediated, 3 dry-run, 1 blocked by guardrail, 1 denied, 0 failed",
  "title": "Automated remediation actions"
}
```

`status` is `"fail"` if any ledger entry in the period failed execution,
`"pass"` if the period had activity with no failures, and `"info"` if
there was no activity at all - the same three-state convention
`grc-evidence-automation`'s own collectors use.

`sha256` (in the actual output, omitted above for readability) is a hash
of the document's own content, computed the same way that repo computes
it for its collectors - a tamper-evidence check on the evidence itself,
independent of how it's stored.

See `terraform/lambda/common/python/remediation_common/ledger.py`
(`build_evidence_document`) for the exact construction logic, and
`terraform/lambda/export_evidence/handler.py` for how it's invoked on a
schedule.
