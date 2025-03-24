package cert

import (
	"fmt"
	"os"
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

// CertificateType represents the type of certificate
type CertificateType int

const (
	// Root is a self-signed root certificate
	Root CertificateType = iota
	// Intermediate is a CA certificate signed by a root or intermediate
	Intermediate
	// Leaf is an end-entity certificate
	Leaf
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
	Type               CertificateType  `yaml:"type"`
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
	CACert             string           `yaml:"caCert"` // Path to CA certificate
	CAKey              string           `yaml:"caKey"`  // Path to CA private key
}

// SignConfig holds the configuration for signing a certificate
type SignConfig struct {
	CertPath   string `yaml:"certPath"`   // Path to the certificate to sign
	KeyPath    string `yaml:"keyPath"`    // Path to the certificate's private key
	CACertPath string `yaml:"caCertPath"` // Path to the CA certificate
	CAKeyPath  string `yaml:"caKeyPath"`  // Path to the CA private key
	OutputDir  string `yaml:"outputDir"`  // Output directory for the signed certificate
	NoProgress bool   `yaml:"-"`          // Not serialized to YAML
}

// TrustConfig holds the configuration for trusting a certificate
type TrustConfig struct {
	CertPath   string `yaml:"certPath"`  // Path to the certificate to trust
	OutputDir  string `yaml:"outputDir"` // Output directory for the trusted certificate
	NoProgress bool   `yaml:"-"`         // Not serialized to YAML
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
	}

	// Root certificate specific validations
	if c.Type == Root {
		// Root certificates must be Class 2 or higher
		if c.Class < Class2 {
			return fmt.Errorf("root certificates must be Class 2 or higher")
		}
		// Root certificates must use at least 4096-bit keys
		if c.KeySize < 4096 {
			return fmt.Errorf("root certificates must use at least 4096-bit keys")
		}
		// Root certificates should have longer validity (minimum 5 years)
		if c.ValidityDays < 365*5 {
			return fmt.Errorf("root certificates should have at least 5 years validity")
		}
	} else {
		// For non-root certificates, enforce class-specific validity limits
		if c.ValidityDays > maxValidityDays {
			return fmt.Errorf("validity period cannot exceed %d days for Class %d CA", maxValidityDays, c.Class)
		}
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

	// Validate CA certificate and key paths
	if c.CACert == "" {
		return fmt.Errorf("caCert path is required")
	}
	if c.CAKey == "" {
		return fmt.Errorf("caKey path is required")
	}

	// Check if CA certificate exists
	if _, err := os.Stat(c.CACert); os.IsNotExist(err) {
		return fmt.Errorf("CA certificate not found at %s", c.CACert)
	}

	// Check if CA private key exists
	if _, err := os.Stat(c.CAKey); os.IsNotExist(err) {
		return fmt.Errorf("CA private key not found at %s", c.CAKey)
	}

	return nil
}

// Validate checks and sets default values for SignConfig
func (c *SignConfig) Validate() error {
	// Validate certificate paths
	if c.CertPath == "" {
		return fmt.Errorf("certPath is required")
	}
	if c.KeyPath == "" {
		return fmt.Errorf("keyPath is required")
	}
	if c.CACertPath == "" {
		return fmt.Errorf("caCertPath is required")
	}
	if c.CAKeyPath == "" {
		return fmt.Errorf("caKeyPath is required")
	}

	// Check if certificate exists
	if _, err := os.Stat(c.CertPath); os.IsNotExist(err) {
		return fmt.Errorf("certificate not found at %s", c.CertPath)
	}

	// Check if certificate key exists
	if _, err := os.Stat(c.KeyPath); os.IsNotExist(err) {
		return fmt.Errorf("certificate key not found at %s", c.KeyPath)
	}

	// Check if CA certificate exists
	if _, err := os.Stat(c.CACertPath); os.IsNotExist(err) {
		return fmt.Errorf("CA certificate not found at %s", c.CACertPath)
	}

	// Check if CA private key exists
	if _, err := os.Stat(c.CAKeyPath); os.IsNotExist(err) {
		return fmt.Errorf("CA private key not found at %s", c.CAKeyPath)
	}

	// Set default output directory
	if c.OutputDir == "" {
		c.OutputDir = "certs"
	}
	c.OutputDir = filepath.Clean(c.OutputDir)

	return nil
}

// Validate checks and sets default values for TrustConfig
func (c *TrustConfig) Validate() error {
	// Validate certificate path
	if c.CertPath == "" {
		return fmt.Errorf("certPath is required")
	}

	// Check if certificate exists
	if _, err := os.Stat(c.CertPath); os.IsNotExist(err) {
		return fmt.Errorf("certificate not found at %s", c.CertPath)
	}

	// Set default output directory
	if c.OutputDir == "" {
		c.OutputDir = "certs"
	}
	c.OutputDir = filepath.Clean(c.OutputDir)

	return nil
}
