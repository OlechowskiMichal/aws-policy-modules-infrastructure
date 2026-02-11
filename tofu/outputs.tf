output "policy_json" {
  description = "Combined baseline policy (DenyInsecureTransport + DenyLogDeletion + DenyUnencryptedUploads)"
  value       = data.aws_iam_policy_document.baseline.json
}

output "deny_insecure_transport_json" {
  description = "Policy denying S3 operations over non-TLS connections"
  value       = data.aws_iam_policy_document.deny_insecure_transport.json
}

output "deny_log_deletion_json" {
  description = "Policy denying object and object version deletion"
  value       = data.aws_iam_policy_document.deny_log_deletion.json
}

output "deny_unencrypted_uploads_json" {
  description = "Policy denying uploads without the expected server-side encryption"
  value       = data.aws_iam_policy_document.deny_unencrypted_uploads.json
}
