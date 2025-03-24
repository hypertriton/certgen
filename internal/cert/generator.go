package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	certFileMode = 0644
	keyFileMode  = 0600
)

// Result holds the generated certificate and key data
type Result struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

// GenerateCA generates a Certificate Authority certificate and private key
func GenerateCA(config *CAConfig) (*Result, error) {
	progress := NewGenerationProgress("CA Certificate", !config.NoProgress)
	defer progress.Complete()

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid CA configuration: %w", err)
	}

	// Check output directory permissions
	if err := ensureWritableDirectory(config.OutputDir); err != nil {
		return nil, fmt.Errorf("output directory error: %w", err)
	}

	// Generate private key
	progress.StartKeyGen()
	privateKey, err := generatePrivateKey(config.KeySize)
	if err != nil {
		return nil, err
	}
	progress.CompleteKeyGen()

	// Create certificate template
	progress.StartTemplate()
	template, err := createCATemplate(config)
	if err != nil {
		return nil, err
	}
	progress.CompleteTemplate()

	// Sign certificate
	progress.StartSigning()
	cert, err := generateAndSaveCertificate(template, template, &privateKey.PublicKey, privateKey, config.OutputDir, "ca", progress)
	if err != nil {
		return nil, err
	}
	progress.CompleteSigning()

	return &Result{
		Certificate: cert,
		PrivateKey:  privateKey,
	}, nil
}

// GenerateCertificate generates a certificate signed by the provided CA
func GenerateCertificate(config *CertConfig, ca *Result) error {
	progress := NewGenerationProgress("Server Certificate", !config.NoProgress)
	defer progress.Complete()

	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid certificate configuration: %w", err)
	}

	if err := ensureWritableDirectory(config.OutputDir); err != nil {
		return fmt.Errorf("output directory error: %w", err)
	}

	// Generate private key
	progress.StartKeyGen()
	privateKey, err := generatePrivateKey(config.KeySize)
	if err != nil {
		return err
	}
	progress.CompleteKeyGen()

	// Create certificate template
	progress.StartTemplate()
	template, err := createCertTemplate(config)
	if err != nil {
		return err
	}
	progress.CompleteTemplate()

	// Sign certificate
	progress.StartSigning()
	_, err = generateAndSaveCertificate(template, ca.Certificate, &privateKey.PublicKey, ca.PrivateKey, config.OutputDir, "cert", progress)
	if err != nil {
		return err
	}
	progress.CompleteSigning()

	return nil
}

// Helper functions

func generatePrivateKey(keySize int) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("generating private key: %w", err)
	}
	return key, nil
}

func createCATemplate(config *CAConfig) (*x509.Certificate, error) {
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         config.CommonName,
			Organization:       []string{config.Organization},
			OrganizationalUnit: []string{config.OrganizationalUnit},
			Country:            []string{config.Country},
			Province:           []string{config.Province},
			Locality:           []string{config.Locality},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, config.ValidityDays),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          generateSubjectKeyID(),
		AuthorityKeyId:        generateSubjectKeyID(), // For root CA, AuthorityKeyId = SubjectKeyId
	}

	// Configure class-specific settings
	switch config.Class {
	case Class1:
		template.MaxPathLen = 0 // No intermediate CAs for Class 1
		template.MaxPathLenZero = true
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection}
	case Class2:
		template.MaxPathLen = 1 // Allow one level of intermediate CAs
		template.MaxPathLenZero = false
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	case Class3:
		template.MaxPathLen = 2 // Allow two levels of intermediate CAs
		template.MaxPathLenZero = false
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning}
		template.PolicyIdentifiers = []asn1.ObjectIdentifier{{2, 5, 29, 32, 0}} // Any Policy
	}

	// Root certificate specific settings
	if config.Type == Root {
		// Root certificates are self-signed
		template.AuthorityKeyId = template.SubjectKeyId
		// Root certificates should have longer validity
		template.NotAfter = now.AddDate(0, 0, config.ValidityDays)
		// Root certificates should have specific key usage
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
		// Root certificates should have specific extensions
		template.ExtKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageCodeSigning,
			x509.ExtKeyUsageEmailProtection,
			x509.ExtKeyUsageTimeStamping,
		}
		// Root certificates should have specific policies
		template.PolicyIdentifiers = []asn1.ObjectIdentifier{
			{2, 5, 29, 32, 0}, // Any Policy
			{2, 5, 29, 32, 1}, // CA Policy
		}
	}

	return template, nil
}

func generateSubjectKeyID() []byte {
	id := make([]byte, 20)
	rand.Read(id)
	return id
}

func createCertTemplate(config *CertConfig) (*x509.Certificate, error) {
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         config.CommonName,
			Organization:       []string{config.Organization},
			OrganizationalUnit: []string{config.OrganizationalUnit},
			Country:            []string{config.Country},
			Province:           []string{config.Province},
			Locality:           []string{config.Locality},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, config.ValidityDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		DNSNames:              config.DNSNames,
	}

	// Configure class-specific settings
	switch config.Class {
	case Class1:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection}
	case Class2:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	case Class3:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		template.PolicyIdentifiers = []asn1.ObjectIdentifier{{2, 5, 29, 32, 0}} // Any Policy
	}

	return template, nil
}

func generateAndSaveCertificate(template, parent *x509.Certificate, pub *rsa.PublicKey, priv *rsa.PrivateKey, outDir, prefix string, progress *GenerationProgress) (*x509.Certificate, error) {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("creating certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}

	// Use a WaitGroup to ensure both files are written
	var wg sync.WaitGroup
	var certErr, keyErr error

	progress.StartSaving()
	wg.Add(2)
	go func() {
		defer wg.Done()
		certErr = saveCertificate(filepath.Join(outDir, prefix+".crt"), derBytes)
	}()
	go func() {
		defer wg.Done()
		keyErr = savePrivateKey(filepath.Join(outDir, prefix+".key"), priv)
	}()
	wg.Wait()
	progress.CompleteSaving()

	if certErr != nil {
		return nil, fmt.Errorf("saving certificate: %w", certErr)
	}
	if keyErr != nil {
		return nil, fmt.Errorf("saving private key: %w", keyErr)
	}

	return cert, nil
}

func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}
	return serialNumber, nil
}

func saveCertificate(path string, derBytes []byte) error {
	certOut, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, certFileMode)
	if err != nil {
		return fmt.Errorf("creating certificate file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("encoding certificate: %w", err)
	}
	return nil
}

func savePrivateKey(path string, privateKey *rsa.PrivateKey) error {
	keyOut, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, keyFileMode)
	if err != nil {
		return fmt.Errorf("creating private key file: %w", err)
	}
	defer keyOut.Close()

	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}); err != nil {
		return fmt.Errorf("encoding private key: %w", err)
	}
	return nil
}

func ensureWritableDirectory(dir string) error {
	// Check if directory exists
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// Create directory with appropriate permissions
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("creating directory: %w", err)
			}
			return nil
		}
		return fmt.Errorf("checking directory: %w", err)
	}

	// Check if it's a directory
	if !info.IsDir() {
		return fmt.Errorf("path exists but is not a directory")
	}

	// Check if we can write to it
	testFile := filepath.Join(dir, ".test")
	f, err := os.OpenFile(testFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return fmt.Errorf("directory is not writable")
	}
	f.Close()
	os.Remove(testFile)

	return nil
}
