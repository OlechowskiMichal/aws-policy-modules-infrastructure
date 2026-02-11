package test

import (
	"testing"

	"github.com/gruntwork-io/terratest/modules/terraform"
	test_structure "github.com/gruntwork-io/terratest/modules/test-structure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBaselinePolicyStructure_KMS(t *testing.T) {
	t.Parallel()

	opts := applyFixture(t, "default")
	doc := parsePolicy(t, terraform.Output(t, opts, "kms_policy_json"))

	require.Len(t, doc.Statement, 3, "baseline policy should contain exactly 3 statements")

	expectedSIDs := []string{"DenyInsecureTransport", "DenyLogDeletion", "DenyUnencryptedUploads"}
	for i, sid := range expectedSIDs {
		assert.Equal(t, sid, doc.Statement[i].Sid, "statement %d should have Sid=%q", i, sid)
	}

	transport := findStatement(t, doc, "DenyInsecureTransport")
	assert.Equal(t, "Deny", transport.Effect, "DenyInsecureTransport should have Deny effect")
	assert.Contains(t, transport.Resource, "arn:aws:s3:::test-bucket-kms",
		"DenyInsecureTransport should reference bucket ARN")
	assert.Contains(t, transport.Resource, "arn:aws:s3:::test-bucket-kms/*",
		"DenyInsecureTransport should reference bucket objects ARN")

	deletion := findStatement(t, doc, "DenyLogDeletion")
	assert.Equal(t, "Deny", deletion.Effect, "DenyLogDeletion should have Deny effect")

	uploadsDoc := parsePolicy(t, terraform.Output(t, opts, "kms_deny_unencrypted_uploads_json"))
	assert.Equal(t, "aws:kms", extractSSEConditionValue(t, &uploadsDoc.Statement[0]),
		"KMS variant should require aws:kms encryption")
}

func TestBaselinePolicyStructure_AES256(t *testing.T) {
	t.Parallel()

	opts := applyFixture(t, "default")
	doc := parsePolicy(t, terraform.Output(t, opts, "aes256_deny_unencrypted_uploads_json"))

	require.Len(t, doc.Statement, 1, "individual output should contain exactly 1 statement")
	assert.Equal(t, "DenyUnencryptedUploads", doc.Statement[0].Sid,
		"statement should have Sid=DenyUnencryptedUploads")

	assert.Equal(t, "AES256", extractSSEConditionValue(t, &doc.Statement[0]),
		"AES256 variant should require AES256 encryption")
}

func TestIndividualOutputs(t *testing.T) {
	t.Parallel()

	opts := applyFixture(t, "default")

	outputs := map[string]string{
		"kms_deny_insecure_transport_json":  "DenyInsecureTransport",
		"kms_deny_log_deletion_json":        "DenyLogDeletion",
		"kms_deny_unencrypted_uploads_json": "DenyUnencryptedUploads",
	}

	for outputName, expectedSID := range outputs {
		doc := parsePolicy(t, terraform.Output(t, opts, outputName))

		require.Len(t, doc.Statement, 1,
			"individual output %q should contain exactly 1 statement", outputName)
		assert.Equal(t, expectedSID, doc.Statement[0].Sid,
			"individual output %q should have Sid=%q", outputName, expectedSID)
	}
}

func TestComposition(t *testing.T) {
	t.Parallel()

	opts := applyFixture(t, "composition")
	doc := parsePolicy(t, terraform.Output(t, opts, "composed_policy_json"))

	require.Len(t, doc.Statement, 4,
		"composed policy should contain 4 statements (3 baseline + 1 custom)")

	expectedSIDs := []string{
		"DenyInsecureTransport", "DenyLogDeletion",
		"DenyUnencryptedUploads", "AllowServiceWrite",
	}
	for i, sid := range expectedSIDs {
		assert.Equal(t, sid, doc.Statement[i].Sid, "statement %d should have Sid=%q", i, sid)
	}

	assert.Equal(t, "Allow", findStatement(t, doc, "AllowServiceWrite").Effect,
		"AllowServiceWrite should have Allow effect")
}

func TestValidation_InvalidSSEAlgorithm(t *testing.T) {
	t.Parallel()

	fixtureDir := test_structure.CopyTerraformFolderToTemp(t, "..", "test/fixtures/invalid_sse")

	opts := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir:    fixtureDir,
		TerraformBinary: "tofu",
	})

	_, err := terraform.InitAndPlanE(t, opts)
	require.Error(t, err, "plan should fail with invalid sse_algorithm")
	assert.Contains(t, err.Error(), "sse_algorithm must be",
		"error should mention the validation constraint")
}
