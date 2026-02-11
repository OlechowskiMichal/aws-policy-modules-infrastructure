# Agent Instructions: aws-policy-modules

## Overview

Reusable AWS IAM policy document modules for OpenTofu. Provides composable, deny-by-default security policies that can be merged with bucket-specific statements via `source_policy_documents`.

## Tech Stack

| Component | Tool | Version |
|-----------|------|---------|
| IaC | OpenTofu | ~> 1.9 |
| Cloud | AWS | ~> 5.0 provider |
| Testing | Go + Terratest | 1.23 |
| Linting | golangci-lint | 1.62 (custom build) |
| CI/CD | GitHub Actions | v4 |
| Task runner | Task | 3.x |
| Tool management | mise | latest |
| Git hooks | lefthook | latest |
| Commit lint | commitlint | 19.x |
| Terraform lint | tflint | latest (AWS plugin) |

## Key Files

```text
tofu/main.tf         # Policy document data sources
tofu/variables.tf    # Input variables (bucket_arn, sse_algorithm)
tofu/outputs.tf      # Combined and individual policy JSON outputs
tofu/versions.tf     # Provider requirements (no backend)
test/                # Go/Terratest tests
```

## Module Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `bucket_arn` | string | (required) | ARN of the S3 bucket to protect |
| `sse_algorithm` | string | `aws:kms` | Expected SSE algorithm (`aws:kms` or `AES256`) |

## Module Outputs

| Output | Description |
|--------|-------------|
| `policy_json` | Combined baseline policy (all 3 deny statements) |
| `deny_insecure_transport_json` | Denies S3 operations over non-TLS connections |
| `deny_log_deletion_json` | Denies object and object version deletion |
| `deny_unencrypted_uploads_json` | Denies uploads without expected SSE |

## Commands

```bash
task setup              # Install tools and git hooks
task tofu:fmt           # Format OpenTofu files
task tofu:validate      # Init and validate
task tofu:tflint        # Run tflint
task lint:go            # Run golangci-lint
task test:unit          # Unit tests (no AWS credentials needed)
task ci:validate        # Full CI validation
```

## Development Guidelines

- Follow existing HCL patterns and naming conventions
- Conventional commits enforced via lefthook
- Use feature branches, create PRs
- Run `task ci:validate` before pushing
- Go source files must be <= 120 lines (test files excluded)
- No provider configuration in module — consumers configure providers
- No backend configuration — this is a library module, not a deployment
