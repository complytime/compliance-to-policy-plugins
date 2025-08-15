package server

import (
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
)

// Assisted by: Gemini 2.5 Flash

type output struct {
	Result rego.ResultSet `json:"result"`
}

// NormalizedOPAResult represents the consistent structure your application expects
// from any OPA policy decision.
type NormalizedOPAResult struct {
	Passed          bool     `json:"passed"`
	PolicyId        string   `json:"policy_id"`
	Reason          string   `json:"reason,omitempty"`
	Violations      []string `json:"violations,omitempty"`
	Recommendations []string `json:"recommendations,omitempty"` // Example: for audit policies

	// New fields for evaluated resource information
	EvaluatedResourceID   string `json:"evaluated_resource_id,omitempty"`
	EvaluatedResourceType string `json:"evaluated_resource_type,omitempty"`
	EvaluatedResourceName string `json:"evaluated_resource_name,omitempty"`

	// Add any other fields you want to standardize
	Metadata  map[string]interface{} `json:"metadata,omitempty"` // For any extra, unstructured info
	Error     string                 `json:"error,omitempty"`
	RawResult interface{}            `json:"-"` // Keep original for debugging/logging, but don't marshal
}

// NormalizeOPAResult converts an OPA decision.Result (interface{}) into a consistent NormalizedOPAResult struct.
func NormalizeOPAResult(rawResult rego.ResultSet) []NormalizedOPAResult {
	var normalizedResults []NormalizedOPAResult

	for _, results := range rawResult {
		for _, expression := range results.Expressions {
			value, ok := expression.Value.(map[string]interface{})
			if ok {
				normalized := NormalizedOPAResult{
					Passed:    false,
					Reason:    "No decision or explicitly denied by policy.",
					RawResult: rawResult,
				}

				if passed, ok := value["pass"].(bool); ok {
					normalized.Passed = passed
					if passed {
						normalized.Reason = "Policy passed validation."
					} else {
						normalized.Reason = "Policy failed validation."
					}
				}

				if policyId, ok := value["policy_id"].(string); ok {
					normalized.PolicyId = policyId
				}

				if violations, ok := value["violation"].(map[string]interface{}); ok {
					for v := range violations {
						normalized.Violations = append(normalized.Violations, v)
					}
					if len(normalized.Violations) > 0 {
						normalized.Passed = false                              // If violations exist, typically not allowed
						if !strings.Contains(normalized.Reason, "violation") { // Avoid redundant messages
							normalized.Reason = "Policy denied due to violations."
						}
					}
				}

				if errorMsg, ok := value["error"].(string); ok {
					normalized.Error = errorMsg
					normalized.Passed = false // An explicit error usually means not allowed
					normalized.Reason = fmt.Sprintf("Policy reported an error: %s", errorMsg)
				}

				// Optionally gave resource information if available
				if resourceID, ok := value["evaluation_resource_id"].(string); ok {
					normalized.EvaluatedResourceID = resourceID
				}
				if resourceType, ok := value["evaluation_resource_type"].(string); ok {
					normalized.EvaluatedResourceType = resourceType
				}
				if resourceName, ok := value["evaluation_resource_name"].(string); ok {
					normalized.EvaluatedResourceName = resourceName
				}

				// If we found 'pass' in the map, and no violations, default reason is "pass"
				if normalized.Passed && len(normalized.Violations) == 0 && normalized.Reason == "No decision or explicitly denied by policy." {
					normalized.Reason = "Policy allowed access."
				}
				normalizedResults = append(normalizedResults, normalized)
			}
		}
	}

	return normalizedResults
}

func mapResults(results NormalizedOPAResult) policy.Result {
	if len(results.Violations) == 0 && results.Passed && results.Error != "" {
		return policy.ResultPass
	}

	if results.Error != "" {
		return policy.ResultError
	}
	return policy.ResultFail
}
