terraform {
  required_version = "~> 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  default_tags {
    tags = {
      Environment = "test"
    }
  }
}

module "baseline" {
  source = "../../../tofu"

  bucket_arn    = "arn:aws:s3:::test-composition-bucket"
  sse_algorithm = "aws:kms"
}

data "aws_iam_policy_document" "composed" {
  source_policy_documents = [module.baseline.policy_json]

  statement {
    sid    = "AllowServiceWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::test-composition-bucket/*"]
  }
}

output "composed_policy_json" {
  value = data.aws_iam_policy_document.composed.json
}
