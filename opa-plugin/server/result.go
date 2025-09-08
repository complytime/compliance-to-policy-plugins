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
	"encoding/json"
	"fmt"
	"math"
	"time"

	ocsf "github.com/Santiago-Labs/go-ocsf/ocsf/v1_5_0"
	"github.com/complytime/complybeacon/proofwatch"
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

func (r *Report) ToOCSF(checkId string) (proofwatch.Evidence, error) {
	classUID := 6007
	categoryUID := 6
	categoryName := "Application Activity"
	className := "Scan Activity"
	completedScan := 60070

	// Map operation to OCSF activity type
	var activityID int
	var activityName string
	var typeName string

	vendorName := "conforma"
	productName := "conforma"
	unknown := "unknown"
	unknownID := int32(0)
	action := "observed"
	actionId := int32(3)
	status, statusID := mapReportStatus(*r)

	numFilesInt := len(r.FilePaths)
	if numFilesInt > math.MaxInt32 {
		return proofwatch.Evidence{}, fmt.Errorf("number of files (%d) exceeds the maximum value for an int32 (%d)", numFilesInt, math.MaxInt32)
	}
	numFiles := int32(numFilesInt)

	uid := fmt.Sprintf("c2p-conforma-%s", r.Policy.Name)
	activity := ocsf.ScanActivity{
		ActivityId:   int32(activityID),
		ActivityName: &activityName,
		CategoryName: &categoryName,
		CategoryUid:  int32(categoryUID),
		ClassName:    &className,
		ClassUid:     int32(classUID),
		Status:       &status,
		StatusId:     &statusID,
		Severity:     &unknown,
		SeverityId:   unknownID,
		NumFiles:     &numFiles,
		Metadata: ocsf.Metadata{
			Uid: &uid,
			Product: ocsf.Product{
				Name:       &productName,
				VendorName: &vendorName,
				Version:    &r.EcVersion,
			},
			Version:     r.EcVersion,
			LogProvider: &productName,
		},
		Time:     r.EffectiveTime.UnixMilli(),
		TypeName: &typeName,
		TypeUid:  int64(completedScan),
	}

	policyData, err := json.Marshal(r.Policy)
	if err != nil {
		return proofwatch.Evidence{}, err
	}
	policyDataStr := string(policyData)

	policy := ocsf.Policy{
		Name: &r.Policy.Name,
		Uid:  &checkId,
		Data: &policyDataStr,
		Desc: &r.Policy.Description,
	}

	files := "File Name"
	for _, input := range r.FilePaths {
		observable := ocsf.Observable{
			Name:   &input.FilePath,
			Type:   &files,
			TypeId: int32(7),
		}
		activity.Observables = append(activity.Observables, &observable)
	}

	evidenceEvent := proofwatch.Evidence{
		ScanActivity: activity,
		Policy:       policy,
		Action:       &action,
		ActionID:     &actionId,
	}

	return evidenceEvent, nil
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
