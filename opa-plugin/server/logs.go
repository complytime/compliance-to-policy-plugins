package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	ocsf "github.com/Santiago-Labs/go-ocsf/ocsf/v1_5_0"
)

func ReportToActivity(report Report) (ocsf.APIActivity, error) {
	classUID := 6003
	categoryUID := 6
	categoryName := "Application Activity"
	className := "API Activity"
	completedScan := 60070

	// Map operation to OCSF activity type
	var activityID int
	var activityName string
	var typeName string

	vendorName := "conforma"
	productName := "conforma"

	unknown := "unknown"
	unknownID := int32(0)

	status, statusID := mapReportStatus(report)

	var resources []*ocsf.ResourceDetails
	for _, filepath := range report.FilePaths {
		resource := &ocsf.ResourceDetails{
			Name: &filepath.FilePath,
		}
		resources = append(resources, resource)
	}

	activity := ocsf.APIActivity{
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
		Resources:    resources,
		Metadata: ocsf.Metadata{
			Product: ocsf.Product{
				Name:       &productName,
				VendorName: &vendorName,
			},
			Version: report.EcVersion,
		},
		Time:     report.EffectiveTime.UnixMilli(),
		TypeName: &typeName,
		TypeUid:  int64(completedScan),
	}

	return activity, nil
}

func PushEvidence(ctx context.Context, endpoint string, activity ocsf.APIActivity) error {
	payload, err := json.Marshal(activity)
	if err != nil {
		return fmt.Errorf("marshal evidence: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("post to proofwatch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("proofwatch push failed: %s: %s", resp.Status, string(body))
	}
	return nil
}
