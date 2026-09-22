# Evidence bucket: export_evidence.handler writes one JSON document per
# (account, region, day) here. Not public, encrypted, versioned so an
# overwritten evidence document doesn't destroy the prior day's proof.

resource "aws_s3_bucket" "access_logs" {
  # checkov:skip=CKV_AWS_144: cross-region replication is a per-deployment
  # decision, not something this module should force.
  # checkov:skip=CKV_AWS_18: this bucket *is* the access-log destination
  # for the evidence bucket below - it doesn't log itself.
  # checkov:skip=CKV2_AWS_62: pure log-delivery target; nothing meaningful
  # to react to via event notifications.
  # checkov:skip=CKV_AWS_145: S3 server access logging only supports
  # SSE-S3 on the destination bucket, not SSE-KMS - an AWS-documented
  # constraint, not a choice made here.
  bucket        = "${local.name_prefix}-access-logs-${local.account_id}-${local.region}"
  force_destroy = var.evidence_bucket_force_destroy
  tags          = local.common_tags
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "access_logs" {
  # Buckets created by this provider version default to ACLs disabled
  # (BucketOwnerEnforced), so the classic "log delivery group" ACL grant
  # aws_s3_bucket_logging otherwise relies on won't take effect - this
  # policy is the modern, AWS-documented replacement for S3 server access
  # logging under that ownership setting.
  bucket = aws_s3_bucket.access_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "S3ServerAccessLogsPolicy"
      Effect    = "Allow"
      Principal = { Service = "logging.s3.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = "${aws_s3_bucket.access_logs.arn}/*"
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account_id }
        ArnLike      = { "aws:SourceArn" = aws_s3_bucket.evidence.arn }
      }
    }]
  })
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    id     = "expire-old-access-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = 365
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket" "evidence" {
  # checkov:skip=CKV_AWS_144: cross-region replication is a per-deployment
  # decision (depends on the org's DR posture), not something this module
  # should force; intentionally left to the operator.
  # checkov:skip=CKV2_AWS_62: event notifications would fire on every
  # daily evidence write - noise, not signal, for a batch export bucket
  # with one writer (export_evidence) and no downstream consumer that
  # needs to be pushed to rather than pulling on its own schedule.
  bucket        = "${local.name_prefix}-evidence-${local.account_id}-${local.region}"
  force_destroy = var.evidence_bucket_force_destroy
  tags          = local.common_tags
}

resource "aws_s3_bucket_logging" "evidence" {
  bucket        = aws_s3_bucket.evidence.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "evidence-bucket-access-logs/"
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    id     = "expire-noncurrent-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 365
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}
