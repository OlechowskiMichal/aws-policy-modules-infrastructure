variable "bucket_arn" {
  description = "ARN of the S3 bucket to protect"
  type        = string
}

variable "sse_algorithm" {
  description = "Expected SSE algorithm. Valid: aws:kms, AES256"
  type        = string
  default     = "aws:kms"

  validation {
    condition     = contains(["aws:kms", "AES256"], var.sse_algorithm)
    error_message = "sse_algorithm must be \"aws:kms\" or \"AES256\""
  }
}
