package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ghodss/yaml"
	"github.com/open-policy-agent/opa/v1/compile"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
	cp "github.com/otiai10/copy"
	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
)

type Composer struct {
	policiesTemplates string
	policyOutput      string
	conformaPolicy    string
}

func NewComposer(policiesTemplates string, output string) *Composer {
	return &Composer{
		policiesTemplates: policiesTemplates,
		policyOutput:      output,
	}
}

func (c *Composer) GetPoliciesDir() string {
	return c.policiesTemplates
}

func (c *Composer) Bundle(ctx context.Context, config Config) error {
	buf := bytes.NewBuffer(nil)

	compiler := compile.New().
		WithRevision(config.BundleRevision).
		WithOutput(buf).
		WithPaths(config.PolicyOutput)

	compiler = compiler.WithRegoVersion(regoVersion)

	err := compiler.Build(ctx)
	if err != nil {
		return err
	}

	out, err := os.Create(config.Bundle)
	if err != nil {
		return err
	}

	_, err = io.Copy(out, buf)
	if err != nil {
		return err
	}
	return nil
}

func (c *Composer) GeneratePolicySet(pl policy.Policy, config Config) error {

	outputDir := c.policyOutput
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory %s: %w", outputDir, err)
	}

	conformaPolicy := ecc.EnterpriseContractPolicySpec{
		Name:        "",
		Description: "",
	}

	// There does not have to be a file for every single one
	for _, rule := range pl {
		parameterMap := map[string]string{}
		source := ecc.Source{
			Name: rule.Rule.ID,
			Policy: []string{
				config.BundleTargetLocation,
			},
			Config: &ecc.SourceConfig{},
		}

		for _, prm := range rule.Rule.Parameters {
			parameterMap[prm.ID] = prm.Value
		}

		// Add policy rule data
		if len(parameterMap) > 0 {
			policyConfigData, err := yaml.Marshal(parameterMap)
			if err != nil {
				return err
			}
			source.RuleData = &v1.JSON{Raw: policyConfigData}
		}

		// Copy over in-scope policies checks for the assessment
		for _, check := range rule.Checks {
			source.Config.Include = append(source.Config.Include, check.ID)
			origfilePath := filepath.Join(c.policiesTemplates, fmt.Sprintf("%s.rego", check.ID))
			destfilePath := filepath.Join(outputDir, fmt.Sprintf("%s.rego", check.ID))
			if err := cp.Copy(origfilePath, destfilePath); err != nil {
				return err
			}
		}
		conformaPolicy.Sources = append(conformaPolicy.Sources, source)
	}

	// Write out one `policy.yaml` per check
	configFileName := filepath.Join(outputDir, "policy.yaml")
	policyData, err := yaml.Marshal(conformaPolicy)
	if err != nil {
		return fmt.Errorf("error marshalling conforma policy data: %w", err)
	}
	if err := os.WriteFile(configFileName, policyData, 0644); err != nil {
		return fmt.Errorf("failed to write policy config to %s: %w", configFileName, err)
	}

	return nil
}
