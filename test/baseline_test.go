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

	fixtureDir := test_structure.CopyTerraformFolderToTemp(t, "..", "test/fixtures/default")

	opts := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir:    fixtureDir,
		TerraformBinary: "tofu",
	})

	t.Cleanup(func() { terraform.Destroy(t, opts) })
	terraform.InitAndApply(t, opts)

	policyJSON := terraform.Output(t, opts, "kms_policy_json")
	doc := parsePolicy(t, policyJSON)

	require.Len(t, doc.Statement, 3, "baseline policy should contain exactly 3 statements")

	expectedSIDs := []string{"DenyInsecureTransport", "DenyLogDeletion", "DenyUnencryptedUploads"}
	for i, expectedSID := range expectedSIDs {
		assert.Equal(t, expectedSID, doc.Statement[i].Sid,
			"statement %d should have Sid=%q", i, expectedSID)
	}

	transport := findStatement(t, doc, "DenyInsecureTransport")
	assert.Equal(t, "Deny", transport.Effect, "DenyInsecureTransport should have Deny effect")
	assert.Contains(t, transport.Resource, "arn:aws:s3:::test-bucket-kms",
		"DenyInsecureTransport should reference bucket ARN")
	assert.Contains(t, transport.Resource, "arn:aws:s3:::test-bucket-kms/*",
		"DenyInsecureTransport should reference bucket objects ARN")

	deletion := findStatement(t, doc, "DenyLogDeletion")
	assert.Equal(t, "Deny", deletion.Effect, "DenyLogDeletion should have Deny effect")

	uploads := findStatement(t, doc, "DenyUnencryptedUploads")
	assert.Equal(t, "Deny", uploads.Effect, "DenyUnencryptedUploads should have Deny effect")

	uploadsJSON := terraform.Output(t, opts, "kms_deny_unencrypted_uploads_json")
	uploadsDoc := parsePolicy(t, uploadsJSON)
	uploadsStmt := uploadsDoc.Statement[0]

	condMap, ok := uploadsStmt.Condition.(map[string]interface{})
	require.True(t, ok, "condition should be a map")

	nestedCond, ok := condMap["StringNotEqualsIfExists"].(map[string]interface{})
	require.True(t, ok, "condition should contain StringNotEqualsIfExists")

	sseValue := nestedCond["s3:x-amz-server-side-encryption"]
	assert.Equal(t, "aws:kms", sseValue, "KMS variant should require aws:kms encryption")
}

func TestBaselinePolicyStructure_AES256(t *testing.T) {
	t.Parallel()

	fixtureDir := test_structure.CopyTerraformFolderToTemp(t, "..", "test/fixtures/default")

	opts := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir:    fixtureDir,
		TerraformBinary: "tofu",
	})

	t.Cleanup(func() { terraform.Destroy(t, opts) })
	terraform.InitAndApply(t, opts)

	uploadsJSON := terraform.Output(t, opts, "aes256_deny_unencrypted_uploads_json")
	doc := parsePolicy(t, uploadsJSON)

	require.Len(t, doc.Statement, 1, "individual output should contain exactly 1 statement")

	stmt := doc.Statement[0]
	assert.Equal(t, "DenyUnencryptedUploads", stmt.Sid, "statement should have Sid=DenyUnencryptedUploads")

	condMap, ok := stmt.Condition.(map[string]interface{})
	require.True(t, ok, "condition should be a map")

	nestedCond, ok := condMap["StringNotEqualsIfExists"].(map[string]interface{})
	require.True(t, ok, "condition should contain StringNotEqualsIfExists")

	sseValue := nestedCond["s3:x-amz-server-side-encryption"]
	assert.Equal(t, "AES256", sseValue, "AES256 variant should require AES256 encryption")
}

func TestIndividualOutputs(t *testing.T) {
	t.Parallel()

	fixtureDir := test_structure.CopyTerraformFolderToTemp(t, "..", "test/fixtures/default")

	opts := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir:    fixtureDir,
		TerraformBinary: "tofu",
	})

	t.Cleanup(func() { terraform.Destroy(t, opts) })
	terraform.InitAndApply(t, opts)

	outputs := map[string]string{
		"kms_deny_insecure_transport_json":  "DenyInsecureTransport",
		"kms_deny_log_deletion_json":        "DenyLogDeletion",
		"kms_deny_unencrypted_uploads_json": "DenyUnencryptedUploads",
	}

	for outputName, expectedSID := range outputs {
		policyJSON := terraform.Output(t, opts, outputName)
		doc := parsePolicy(t, policyJSON)

		require.Len(t, doc.Statement, 1,
			"individual output %q should contain exactly 1 statement", outputName)
		assert.Equal(t, expectedSID, doc.Statement[0].Sid,
			"individual output %q should have Sid=%q", outputName, expectedSID)
	}
}

func TestComposition(t *testing.T) {
	t.Parallel()

	fixtureDir := test_structure.CopyTerraformFolderToTemp(t, "..", "test/fixtures/composition")

	opts := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir:    fixtureDir,
		TerraformBinary: "tofu",
	})

	t.Cleanup(func() { terraform.Destroy(t, opts) })
	terraform.InitAndApply(t, opts)

	composedJSON := terraform.Output(t, opts, "composed_policy_json")
	doc := parsePolicy(t, composedJSON)

	require.Len(t, doc.Statement, 4,
		"composed policy should contain 4 statements (3 baseline + 1 custom)")

	expectedSIDs := []string{
		"DenyInsecureTransport",
		"DenyLogDeletion",
		"DenyUnencryptedUploads",
		"AllowServiceWrite",
	}

	for i, expectedSID := range expectedSIDs {
		assert.Equal(t, expectedSID, doc.Statement[i].Sid,
			"statement %d should have Sid=%q", i, expectedSID)
	}

	allow := findStatement(t, doc, "AllowServiceWrite")
	assert.Equal(t, "Allow", allow.Effect, "AllowServiceWrite should have Allow effect")
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
