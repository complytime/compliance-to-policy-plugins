package server

import (
	"bytes"
	"context"
	"encoding/json"
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
	var local bool
	outputDir := c.policyOutput
	if config.PolicyTemplates != "" {
		local = true
		outputDir = filepath.Join(c.policyOutput, "policy")
		if err := os.MkdirAll(outputDir, 0750); err != nil {
			return fmt.Errorf("failed to create output directory %s: %w", outputDir, err)
		}
	}

	conformaPolicy := ecc.EnterpriseContractPolicySpec{
		Name:        "C2P Policy",
		Description: "Policy Created by C2P",
	}

	// There does not have to be a file for every single one
	for _, rule := range pl {
		parameterMap := map[string]string{}
		source := ecc.Source{
			Name:   rule.Rule.ID,
			Policy: []string{config.BundleLocation},
			Config: &ecc.SourceConfig{},
		}

		for _, prm := range rule.Rule.Parameters {
			parameterMap[prm.ID] = prm.Value
		}

		// Add policy rule data
		if len(parameterMap) > 0 {
			policyConfigData, err := json.Marshal(parameterMap)
			if err != nil {
				return err
			}
			source.RuleData = &v1.JSON{Raw: policyConfigData}
		}

		for _, check := range rule.Checks {
			source.Config.Include = append(source.Config.Include, check.ID)
			if local {
				// Copy over the check directory
				origfilePath := filepath.Join(c.policiesTemplates, check.ID)
				destfilePath := filepath.Join(outputDir, check.ID)
				if err := cp.Copy(origfilePath, destfilePath); err != nil {
					return err
				}
			}
		}
		conformaPolicy.Sources = append(conformaPolicy.Sources, source)
	}

	// Write out one `policy.yaml`
	policyFileName := filepath.Join(c.conformaPolicy, "policy.yaml")
	policyData, err := yaml.Marshal(conformaPolicy)
	if err != nil {
		return fmt.Errorf("error marshalling conforma policy data: %w", err)
	}
	if err := os.WriteFile(policyFileName, policyData, 0600); err != nil {
		return fmt.Errorf("failed to write policy config to %s: %w", policyFileName, err)
	}

	return nil
}
