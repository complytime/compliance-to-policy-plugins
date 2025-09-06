package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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

	// Optionally forward logs to otel.
	ForwardLogs   string `mapstructure:"forward-logs"`
	SkipTLS       string `mapstructure:"skip-tls"`
	SkipTLSVerify string `mapstructure:"skip-tls-verify"`

	skipTLS       bool
	skipTLSVerify bool
}

func (c *Config) Complete() (err error) {
	if c.Bundle != "" && c.BundleLocation == "" {
		c.BundleLocation = c.Bundle
	} else if c.PolicyOutput != "" && c.BundleLocation == "" {
		c.BundleLocation = c.PolicyOutput
	}

	if c.ForwardLogs != "" {
		c.skipTLSVerify, err = strconv.ParseBool(c.SkipTLSVerify)
		if err != nil {
			return err
		}
		c.skipTLS, err = strconv.ParseBool(c.SkipTLS)
		if err != nil {
			return err
		}
	}

	return nil
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
