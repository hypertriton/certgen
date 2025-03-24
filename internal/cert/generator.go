package cert

import (
	"certgen/internal/system"
	"crypto"
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

// GenerateCertificate generates a certificate using the provided configuration
func GenerateCertificate(config *CertConfig) error {
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid certificate configuration: %w", err)
	}

	// Create certificate template
	template, err := createCertTemplate(config)
	if err != nil {
		return fmt.Errorf("failed to create certificate template: %w", err)
	}

	// Generate private key
	privKey, err := generatePrivateKey(config.KeySize)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Load CA certificate and private key
	caCert, caKey, err := loadCA(config.CACert, config.CAKey)
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}

	// Generate certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &privKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write certificate and private key
	certPath := filepath.Join(config.OutputDir, "cert.crt")
	keyPath := filepath.Join(config.OutputDir, "cert.key")

	if err := writePEM(certPath, "CERTIFICATE", certDER); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	privKeyPEM, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := writePEM(keyPath, "PRIVATE KEY", privKeyPEM); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

// loadCA loads a CA certificate and private key from files
func loadCA(certPath, keyPath string) (*x509.Certificate, crypto.PrivateKey, error) {
	// Read CA certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode CA certificate")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Read CA private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA private key: %w", err)
	}

	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode CA private key")
	}

	caKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	return caCert, caKey, nil
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

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshaling private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
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

func writePEM(path, blockType string, data []byte) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, &pem.Block{Type: blockType, Bytes: data}); err != nil {
		return fmt.Errorf("failed to encode PEM block: %w", err)
	}
	return nil
}

// SignCertificate signs an existing certificate with a CA
func SignCertificate(config *SignConfig) error {
	progress := NewGenerationProgress("Certificate Signing", !config.NoProgress)
	defer progress.Complete()

	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid signing configuration: %w", err)
	}

	// Load the certificate to be signed
	progress.StartLoading()
	certPEM, err := os.ReadFile(config.CertPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}
	progress.CompleteLoading()

	// Load the certificate's private key
	progress.StartKeyLoading()
	keyPEM, err := os.ReadFile(config.KeyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode private key")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}
	progress.CompleteKeyLoading()

	// Load CA certificate and private key
	progress.StartCALoading()
	caCert, caKey, err := loadCA(config.CACertPath, config.CAKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}
	progress.CompleteCALoading()

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Sign the certificate
	progress.StartSigning()
	certDER, err := x509.CreateCertificate(rand.Reader, cert, caCert, &privKey.(*rsa.PrivateKey).PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to sign certificate: %w", err)
	}
	progress.CompleteSigning()

	// Write the signed certificate
	progress.StartSaving()
	signedCertPath := filepath.Join(config.OutputDir, "signed.crt")
	if err := writePEM(signedCertPath, "CERTIFICATE", certDER); err != nil {
		return fmt.Errorf("failed to write signed certificate: %w", err)
	}
	progress.CompleteSaving()

	return nil
}

// TrustCertificate trusts a certificate in the system
func TrustCertificate(config *TrustConfig) error {
	progress := NewGenerationProgress("Certificate Trust", !config.NoProgress)
	defer progress.Complete()

	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid trust configuration: %w", err)
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Read the certificate
	progress.StartLoading()
	certPEM, err := os.ReadFile(config.CertPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}
	progress.CompleteLoading()

	// Copy the certificate to the output directory
	progress.StartSaving()
	trustedCertPath := filepath.Join(config.OutputDir, "trusted.crt")
	if err := os.WriteFile(trustedCertPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write trusted certificate: %w", err)
	}
	progress.CompleteSaving()

	// Install and trust the certificate
	trustManager := system.NewCertificateTrustManager(progress)
	if err := trustManager.InstallAndTrustCA(trustedCertPath); err != nil {
		return fmt.Errorf("failed to install and trust certificate: %w", err)
	}

	return nil
}
