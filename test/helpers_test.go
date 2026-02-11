package test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// PolicyDocument represents an IAM policy document.
type PolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// Statement represents a single IAM policy statement.
type Statement struct {
	Sid       string      `json:"Sid"`
	Effect    string      `json:"Effect"`
	Action    interface{} `json:"Action"`
	Resource  interface{} `json:"Resource"`
	Condition interface{} `json:"Condition"`
	Principal interface{} `json:"Principal"`
}

func parsePolicy(t *testing.T, policyJSON string) PolicyDocument {
	t.Helper()

	var doc PolicyDocument
	err := json.Unmarshal([]byte(policyJSON), &doc)
	require.NoError(t, err, "policy JSON should be valid: %s", policyJSON)

	return doc
}

func findStatement(t *testing.T, doc PolicyDocument, sid string) Statement {
	t.Helper()

	for _, s := range doc.Statement {
		if s.Sid == sid {
			return s
		}
	}

	require.Failf(t, "statement not found", "no statement with Sid=%q in policy", sid)

	return Statement{}
}
