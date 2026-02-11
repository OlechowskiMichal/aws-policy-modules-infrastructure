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

module "kms" {
  source = "../../../tofu"

  bucket_arn    = "arn:aws:s3:::test-bucket-kms"
  sse_algorithm = "aws:kms"
}

module "aes256" {
  source = "../../../tofu"

  bucket_arn    = "arn:aws:s3:::test-bucket-aes"
  sse_algorithm = "AES256"
}

output "kms_policy_json" {
  value = module.kms.policy_json
}

output "kms_deny_insecure_transport_json" {
  value = module.kms.deny_insecure_transport_json
}

output "kms_deny_log_deletion_json" {
  value = module.kms.deny_log_deletion_json
}

output "kms_deny_unencrypted_uploads_json" {
  value = module.kms.deny_unencrypted_uploads_json
}

output "aes256_policy_json" {
  value = module.aes256.policy_json
}

output "aes256_deny_unencrypted_uploads_json" {
  value = module.aes256.deny_unencrypted_uploads_json
}
