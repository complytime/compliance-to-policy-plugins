package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-hclog"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/oscal-compass/compliance-to-policy-go/v2/logging"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
)

var (
	_           policy.Provider = (*Plugin)(nil)
	logger      hclog.Logger    = logging.NewPluginLogger()
	regoVersion                 = ast.RegoV1
)

func Logger() hclog.Logger {
	return logger
}

type Plugin struct {
	config *Config
}

func NewPlugin() *Plugin {
	return &Plugin{
		config: &Config{},
	}
}

func (p *Plugin) Configure(_ context.Context, m map[string]string) error {
	if err := mapstructure.Decode(m, &p.config); err != nil {
		return errors.New("error decoding configuration")
	}
	p.config.Complete()
	return p.config.Validate()
}

func (p *Plugin) Generate(ctx context.Context, pl policy.Policy) error {
	composer := NewComposer(p.config.PolicyTemplates, p.config.PolicyOutput)
	if err := composer.GeneratePolicySet(pl, *p.config); err != nil {
		return fmt.Errorf("error generating policies: %w", err)
	}

	if p.config.Bundle != "" {
		logger.Info(fmt.Sprintf("Creating policy bundle at %s", p.config.Bundle))
		if err := composer.Bundle(context.Background(), *p.config); err != nil {
			return fmt.Errorf("error creating policy bundle: %w", err)
		}
	}

	return nil
}

func (p *Plugin) GetResults(_ context.Context, pl policy.Policy) (policy.PVPResult, error) {

	policyIndex := NewLoader()
	if err := policyIndex.LoadFromDirectory(p.config.PolicyResults); err != nil {
		return policy.PVPResult{}, fmt.Errorf("failed to load policy results: %w", err)
	}

	var observations []policy.ObservationByCheck
	for _, rule := range pl {
		for _, check := range rule.Checks {
			name := check.ID

			reports := policyIndex.ResultsByPolicyId(name)
			if len(reports) > 0 {
				observation := policy.ObservationByCheck{
					Title:       rule.Rule.ID,
					CheckID:     name,
					Description: fmt.Sprintf("Observation of check %s", name),
					Methods:     []string{"TEST-AUTOMATED"},
					Collected:   time.Now(),
					Subjects:    []policy.Subject{},
				}
				for _, result := range reports {
					observation.Subjects = append(observation.Subjects, results2Subject(result)...)
				}
				observations = append(observations, observation)
			}

		}
	}
	result := policy.PVPResult{
		ObservationsByCheck: observations,
	}
	return result, nil
}

func results2Subject(report Report) []policy.Subject {
	var subjects []policy.Subject
	for _, input := range report.FilePaths {
		subject := policy.Subject{
			Title:       fmt.Sprintf("%s assessment for %s", report.Policy.Name, input.FilePath),
			ResourceID:  input.FilePath,
			Type:        "resource",
			Result:      mapResults(input),
			EvaluatedOn: report.EffectiveTime,
		}

		var sb strings.Builder
		switch subject.Result {
		case policy.ResultPass:
			for _, success := range input.Successes {
				sb.WriteString(success.Message)
			}
		case policy.ResultFail:
			for _, violation := range input.Violations {
				sb.WriteString(violation.Message)
			}
		default:
			sb.WriteString("No reason provided")

		}
		subject.Reason = sb.String()

		subjects = append(subjects, subject)
	}
	return subjects
}
