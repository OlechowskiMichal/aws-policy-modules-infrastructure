# aws-policy-modules

Reusable AWS policy document modules for OpenTofu.

## S3 Baseline Policy

Composable deny-by-default security policies for S3 buckets:

- **DenyInsecureTransport** — blocks non-TLS access
- **DenyLogDeletion** — prevents object and version deletion
- **DenyUnencryptedUploads** — requires server-side encryption

## Usage

```hcl
module "s3_baseline" {
  source        = "git::https://github.com/OlechowskiMichal/aws-policy-modules.git//tofu?ref=v1.0.0"
  bucket_arn    = aws_s3_bucket.my_bucket.arn
  sse_algorithm = "aws:kms"
}

data "aws_iam_policy_document" "my_bucket" {
  source_policy_documents = [module.s3_baseline.policy_json]

  statement {
    sid    = "AllowServiceWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.my_bucket.arn}/*"]
  }
}

resource "aws_s3_bucket_policy" "my_bucket" {
  bucket = aws_s3_bucket.my_bucket.id
  policy = data.aws_iam_policy_document.my_bucket.json
}
```

Individual policy outputs are also available for selective use:

```hcl
data "aws_iam_policy_document" "custom" {
  source_policy_documents = [
    module.s3_baseline.deny_insecure_transport_json,
    module.s3_baseline.deny_unencrypted_uploads_json,
  ]
}
```

## Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `bucket_arn` | `string` | (required) | ARN of the S3 bucket to protect |
| `sse_algorithm` | `string` | `"aws:kms"` | Expected SSE algorithm (`aws:kms` or `AES256`) |

## Outputs

| Output | Description |
|--------|-------------|
| `policy_json` | Combined baseline (all 3 statements) |
| `deny_insecure_transport_json` | Single statement: deny non-TLS |
| `deny_log_deletion_json` | Single statement: deny deletion |
| `deny_unencrypted_uploads_json` | Single statement: deny unencrypted uploads |

## Development

```bash
task setup          # Install tools and git hooks
task tofu:validate  # Init and validate
task test:unit      # Run tests
task ci:validate    # Full CI check
```

## License

MIT
