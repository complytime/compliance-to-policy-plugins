// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"time"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
)

// Duplicated internal structures from: https://github.com/conforma/cli/blob/431ed55c6f3654bc1f2ecd174b9b3dc40b2b2701/internal/input/report.go

type Report struct {
	Success       bool                             `json:"success"`
	FilePaths     []Input                          `json:"filepaths"`
	Policy        ecc.EnterpriseContractPolicySpec `json:"policy"`
	EcVersion     string                           `json:"ec-version"`
	Data          any                              `json:"-"`
	EffectiveTime time.Time                        `json:"effective-time"`
	PolicyInput   [][]byte                         `json:"-"`
}

type Input struct {
	FilePath     string   `json:"filepath"`
	Violations   []Result `json:"violations"`
	Warnings     []Result `json:"warnings"`
	Successes    []Result `json:"successes"`
	Success      bool     `json:"success"`
	SuccessCount int      `json:"success-count"`
}

type Result struct {
	Message  string                 `json:"msg"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	Outputs  []string               `json:"outputs,omitempty"`
}

func mapResults(input Input) policy.Result {
	if input.Success && len(input.Violations) == 0 {
		return policy.ResultPass
	}
	return policy.ResultFail
}

func mapReportStatus(report Report) (string, int32) {
	if report.Success {
		return "success", 1
	}
	return "failure", 2
}
