package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config represents the configuration for the certificate generator
type Config struct {
	CAKeyPath  string `json:"ca_key_path"`
	CACertPath string `json:"ca_cert_path"`
	OutputDir  string `json:"output_dir"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		CAKeyPath:  "ca/ca.key",
		CACertPath: "ca/ca.crt",
		OutputDir:  "output",
	}
}

// LoadConfig loads the configuration from a file
func LoadConfig() (*Config, error) {
	configPath := "config.json"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Create default config if it doesn't exist
		config := DefaultConfig()
		data, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshaling default config: %w", err)
		}
		if err := os.WriteFile(configPath, data, 0644); err != nil {
			return nil, fmt.Errorf("writing default config: %w", err)
		}
		return config, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}

	return &config, nil
}
