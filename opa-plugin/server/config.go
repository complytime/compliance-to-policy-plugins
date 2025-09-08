package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	// Required
	PolicyResults      string `mapstructure:"policy-results"`
	ConformaPolicyPath string `mapstructure:"conforma-policy-path"`

	// Set the bundle location. If creating one locally, this can
	// fall back to the local bundle location.
	BundleLocation string `mapstructure:"bundle-location"`

	// Optionally bundle local policy
	Bundle         string `mapstructure:"bundle"`
	BundleRevision string `mapstructure:"bundle-revision"`

	// Optional if building locally
	PolicyTemplates string `mapstructure:"policy-templates"`
	PolicyOutput    string `mapstructure:"policy-output"`
}

func (c *Config) Complete() {
	if c.Bundle != "" && c.BundleLocation == "" {
		c.BundleLocation = c.Bundle
	} else if c.PolicyOutput != "" && c.BundleLocation == "" {
		c.BundleLocation = c.PolicyOutput
	}
}

func (c *Config) Validate() error {
	var errs []error
	if err := checkPath(&c.PolicyResults); err != nil {
		errs = append(errs, err)
	}

	if err := checkPath(&c.ConformaPolicyPath); err != nil {
		errs = append(errs, err)
	}

	if c.PolicyTemplates != "" {
		if err := checkPath(&c.PolicyOutput); err != nil {
			errs = append(errs, err)
		}

		if err := checkPath(&c.PolicyTemplates); err != nil {
			errs = append(errs, err)
		}
	}

	if c.BundleLocation == "" {
		errs = append(errs, errors.New("bundle-location cannot be empty"))
	}

	return errors.Join(errs...)
}

func checkPath(path *string) error {
	if path != nil && *path != "" {
		cleanedPath := filepath.Clean(*path)
		path = &cleanedPath
		_, err := os.Stat(*path)
		if err != nil {
			return fmt.Errorf("path %q: %w", *path, err)
		}
	}
	return nil
}
