package server

import (
	"testing"

	"github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
	"github.com/stretchr/testify/require"
)

func Test_Results2Subject(t *testing.T) {
	report := Report{
		Policy: v1alpha1.EnterpriseContractPolicySpec{
			Name: "Example",
		},
		FilePaths: []Input{
			{
				FilePath: "input",
				Violations: []Result{
					{
						Message: "Branch protection for 'main' requires pull request reviews " +
							"but has less than the configured minimum of 1 required approving reviews.",
					},
					{
						Message: "Another violation.",
					},
				},
				Success: false,
			},
		},
	}

	expectedSubj := policy.Subject{
		Title:      "Example assessment for input",
		Type:       "resource",
		ResourceID: "input",
		Result:     policy.ResultFail,
		Reason: "Branch protection for 'main' requires pull request reviews " +
			"but has less than the configured minimum of 1 required approving reviews.\\nAnother violation.",
	}

	subject := results2Subject(report)[0]
	require.Equal(t, expectedSubj.Type, subject.Type)
	require.Equal(t, expectedSubj.Reason, subject.Reason)
	require.Equal(t, expectedSubj.Title, subject.Title)
	require.Equal(t, expectedSubj.Result, subject.Result)
}
