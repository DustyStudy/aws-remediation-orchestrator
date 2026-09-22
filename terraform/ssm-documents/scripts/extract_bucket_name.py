"""SSM Automation aws:executeScript step for S3PublicAccessRemediation.

Pulls the bucket name out of the finding's resource ARN
(``arn:<partition>:s3:::bucket-name`` - Security Hub's S3 bucket ARNs never
include a key). Kept as a tiny standalone script (not remediation_common)
because SSM executeScript steps run in their own sandboxed runtime,
separate from the orchestrator's own Lambda/layer packaging.
"""


def handler(events, _context):
    arn = events["ResourceArn"]
    bucket_name = arn.split(":::", 1)[-1].split("/", 1)[0]
    return {"BucketName": bucket_name}
