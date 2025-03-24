package cert

import (
	"fmt"
	"path/filepath"
)

// CertificateClass represents the class of certificate
type CertificateClass int

const (
	// Class1 is for low-assurance certificates (email, personal use)
	Class1 CertificateClass = iota + 1
	// Class2 is for medium-assurance certificates (organization validation)
	Class2
	// Class3 is for high-assurance certificates (extended validation)
	Class3
)

// CAConfig holds the configuration for a Certificate Authority
type CAConfig struct {
	CommonName         string           `yaml:"commonName"`
	Organization       string           `yaml:"organization"`
	OrganizationalUnit string           `yaml:"organizationalUnit"`
	Country            string           `yaml:"country"`
	Province           string           `yaml:"province"`
	Locality           string           `yaml:"locality"`
	ValidityDays       int              `yaml:"validityDays"`
	KeySize            int              `yaml:"keySize"`
	OutputDir          string           `yaml:"outputDir"`
	NoProgress         bool             `yaml:"-"` // Not serialized to YAML
	Class              CertificateClass `yaml:"class"`
}

// CertConfig holds the configuration for a certificate
type CertConfig struct {
	CommonName         string           `yaml:"commonName"`
	Organization       string           `yaml:"organization"`
	OrganizationalUnit string           `yaml:"organizationalUnit"`
	Country            string           `yaml:"country"`
	Province           string           `yaml:"province"`
	Locality           string           `yaml:"locality"`
	ValidityDays       int              `yaml:"validityDays"`
	KeySize            int              `yaml:"keySize"`
	DNSNames           []string         `yaml:"dnsNames"`
	OutputDir          string           `yaml:"outputDir"`
	NoProgress         bool             `yaml:"-"` // Not serialized to YAML
	Class              CertificateClass `yaml:"class"`
}

// getClassRequirements returns the requirements for a certificate class
func getClassRequirements(class CertificateClass) (minKeySize int, maxValidityDays int) {
	switch class {
	case Class1:
		return 2048, 365 * 5 // 5 years max for Class 1
	case Class2:
		return 3072, 365 * 3 // 3 years max for Class 2
	case Class3:
		return 4096, 365 * 2 // 2 years max for Class 3
	default:
		return 2048, 365 * 5 // Default to Class 1 requirements
	}
}

// Validate checks and sets default values for CAConfig
func (c *CAConfig) Validate() error {
	if c.CommonName == "" {
		return fmt.Errorf("commonName is required")
	}
	if c.Organization == "" {
		return fmt.Errorf("organization is required")
	}
	if c.Country == "" {
		return fmt.Errorf("country is required")
	}

	// Set default class if not specified
	if c.Class == 0 {
		c.Class = Class1
	}

	// Get class requirements
	minKeySize, maxValidityDays := getClassRequirements(c.Class)

	// Validate key size
	if c.KeySize <= 0 {
		c.KeySize = minKeySize // Default to minimum for class
	} else if c.KeySize < minKeySize {
		return fmt.Errorf("keySize must be at least %d bits for Class %d CA", minKeySize, c.Class)
	}

	// Validate validity period
	if c.ValidityDays <= 0 {
		c.ValidityDays = maxValidityDays // Default to maximum for class
	} else if c.ValidityDays > maxValidityDays {
		return fmt.Errorf("validity period cannot exceed %d days for Class %d CA", maxValidityDays, c.Class)
	}

	// Set default output directory
	if c.OutputDir == "" {
		c.OutputDir = "certs"
	}
	c.OutputDir = filepath.Clean(c.OutputDir)

	return nil
}

// Validate checks and sets default values for CertConfig
func (c *CertConfig) Validate() error {
	if c.CommonName == "" {
		return fmt.Errorf("commonName is required")
	}
	if c.Organization == "" {
		return fmt.Errorf("organization is required")
	}
	if c.Country == "" {
		return fmt.Errorf("country is required")
	}

	// Set default class if not specified
	if c.Class == 0 {
		c.Class = Class1
	}

	// Get class requirements
	minKeySize, maxValidityDays := getClassRequirements(c.Class)

	// Validate key size
	if c.KeySize <= 0 {
		c.KeySize = minKeySize // Default to minimum for class
	} else if c.KeySize < minKeySize {
		return fmt.Errorf("keySize must be at least %d bits for Class %d certificate", minKeySize, c.Class)
	}

	// Validate validity period
	if c.ValidityDays <= 0 {
		c.ValidityDays = maxValidityDays // Default to maximum for class
	} else if c.ValidityDays > maxValidityDays {
		return fmt.Errorf("validity period cannot exceed %d days for Class %d certificate", maxValidityDays, c.Class)
	}

	// Set default DNS names
	if len(c.DNSNames) == 0 {
		c.DNSNames = []string{c.CommonName}
	}

	// Set default output directory
	if c.OutputDir == "" {
		c.OutputDir = "certs"
	}
	c.OutputDir = filepath.Clean(c.OutputDir)

	return nil
}
