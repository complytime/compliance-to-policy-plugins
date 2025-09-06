package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	ocsf "github.com/Santiago-Labs/go-ocsf/ocsf/v1_5_0"
	"github.com/complytime/complybeacon/proofwatch"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/log/global"
	olog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const name = "compliancetopolicy.evidence.count"

var (
	meter       = otel.Meter(name)
	serviceName = semconv.ServiceNameKey.String("conforma-plugin")
)

func reportToEvidence(checkId string, report Report) (proofwatch.Evidence, error) {
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
	status, statusID := mapReportStatus(report)
	numFiles := int32(len(report.FilePaths))

	uid := fmt.Sprintf("c2p-conforma-%s", report.Policy.Name)
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
				Version:    &report.EcVersion,
			},
			Version:     report.EcVersion,
			LogProvider: &productName,
		},
		Time:     report.EffectiveTime.UnixMilli(),
		TypeName: &typeName,
		TypeUid:  int64(completedScan),
	}

	policyData, err := json.Marshal(report.Policy)
	if err != nil {
		return proofwatch.Evidence{}, err
	}
	policyDataStr := string(policyData)

	policy := ocsf.Policy{
		Name: &report.Policy.Name,
		Uid:  &checkId,
		Data: &policyDataStr,
		Desc: &report.Policy.Description,
	}

	files := "File Name"
	for _, input := range report.FilePaths {
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

// otelSDKSetup completes setup of the Otel SDK with providers.
func otelSDKSetup(ctx context.Context, conn *grpc.ClientConn) (func(context.Context) error, error) {
	var shutdownFuncs []func(context.Context) error
	shutDown := func(ctx context.Context) error {
		var err error
		for _, fn := range shutdownFuncs {
			err = errors.Join(err, fn(ctx))
		}
		shutdownFuncs = nil
		return err
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			serviceName,
		),
	)
	if err != nil {
		return nil, err
	}

	metricExporter, err := otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithGRPCConn(conn))
	if err != nil {
		return nil, err
	}

	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter, sdkmetric.WithInterval(3*time.Second))), sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(meterProvider)

	logExporter, err := otlploggrpc.New(ctx, otlploggrpc.WithGRPCConn(conn))
	if err != nil {
		return nil, err
	}

	logProcessor := olog.NewSimpleProcessor(logExporter)
	logProvider := olog.NewLoggerProvider(olog.WithProcessor(logProcessor), olog.WithResource(res))

	// Register the provider as the global logger provider.
	global.SetLoggerProvider(logProvider)

	shutdownFuncs = append(shutdownFuncs, logProvider.Shutdown, meterProvider.Shutdown)

	return shutDown, nil
}

func newClient(otelEndpoint string, skipTLS, skipTLSVerify bool) (*grpc.ClientConn, error) {
	var creds credentials.TransportCredentials
	if skipTLS {
		creds = insecure.NewCredentials()
	} else {
		sysPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to get system cert: %w", err)
		}
		// By default, skip TLS verify is false.
		creds = credentials.NewTLS(&tls.Config{RootCAs: sysPool, InsecureSkipVerify: skipTLSVerify}) /* #nosec G402 */
	}
	return grpc.NewClient(otelEndpoint, grpc.WithTransportCredentials(creds))
}
