# S3 Baseline Security Policies
#
# Composable deny-by-default policies for any S3 bucket.
# Use `policy_json` for all three, or individual outputs for selective use.

data "aws_iam_policy_document" "deny_insecure_transport" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:*"]
    resources = [var.bucket_arn, "${var.bucket_arn}/*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

data "aws_iam_policy_document" "deny_log_deletion" {
  statement {
    sid    = "DenyLogDeletion"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = [
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
    ]
    resources = ["${var.bucket_arn}/*"]
  }
}

data "aws_iam_policy_document" "deny_unencrypted_uploads" {
  statement {
    sid    = "DenyUnencryptedUploads"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${var.bucket_arn}/*"]

    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption"
      values   = [var.sse_algorithm]
    }
  }
}

data "aws_iam_policy_document" "baseline" {
  source_policy_documents = [
    data.aws_iam_policy_document.deny_insecure_transport.json,
    data.aws_iam_policy_document.deny_log_deletion.json,
    data.aws_iam_policy_document.deny_unencrypted_uploads.json,
  ]
}
