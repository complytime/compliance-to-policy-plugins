package server

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfig_Complete(t *testing.T) {
	tests := []struct {
		name           string
		config         *Config
		expectedConfig Config
		wantErr        string
	}{
		{
			name: "Success/BundleLocationSet",
			config: &Config{
				BundleLocation: "example",
			},
			expectedConfig: Config{
				BundleLocation: "example",
			},
		},
		{
			name: "Success/LocalBundle",
			config: &Config{
				BundleLocation: "",
				PolicyOutput:   "/policy",
			},
			expectedConfig: Config{
				BundleLocation: "/policy",
				PolicyOutput:   "/policy",
			},
		},
		{
			name: "Success/LocalBundle",
			config: &Config{
				BundleLocation: "",
				Bundle:         "bundle.tgz",
				PolicyOutput:   "/policy",
			},
			expectedConfig: Config{
				BundleLocation: "bundle.tgz",
				Bundle:         "bundle.tgz",
				PolicyOutput:   "/policy",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Complete()
			if tt.wantErr != "" {
				require.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedConfig, *tt.config)
			}
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr string
	}{
		{
			name: "Success/Config",
			config: &Config{
				PolicyResults:  "",
				BundleLocation: "example",
			},
		},
		{
			name: "Failure/NoBundleLocation",
			config: &Config{
				BundleLocation: "",
			},
			wantErr: "bundle-location cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr != "" {
				require.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
