package system

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// CertificateTrustManager handles system-level certificate trust operations
type CertificateTrustManager struct {
	progress ProgressReporter
}

// ProgressReporter interface for reporting progress
type ProgressReporter interface {
	StartProgress(description string)
	CompleteProgress()
}

// NewCertificateTrustManager creates a new trust manager
func NewCertificateTrustManager(progress ProgressReporter) *CertificateTrustManager {
	return &CertificateTrustManager{
		progress: progress,
	}
}

// InstallAndTrustCA installs and trusts a CA certificate in the system
func (m *CertificateTrustManager) InstallAndTrustCA(certPath string) error {
	switch runtime.GOOS {
	case "darwin":
		return m.installAndTrustCADarwin(certPath)
	case "linux":
		return m.installAndTrustCALinux(certPath)
	case "windows":
		return m.installAndTrustCAWindows(certPath)
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// InstallCertificate installs a server certificate
func (m *CertificateTrustManager) InstallCertificate(certPath, keyPath string) error {
	// For now, just verify the files exist as we don't need to install server certs
	if _, err := os.Stat(certPath); err != nil {
		return fmt.Errorf("certificate file not found: %w", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		return fmt.Errorf("key file not found: %w", err)
	}
	return nil
}

func (m *CertificateTrustManager) installAndTrustCADarwin(certPath string) error {
	m.progress.StartProgress("Installing CA certificate")
	defer m.progress.CompleteProgress()

	// Get the absolute path
	absPath, err := filepath.Abs(certPath)
	if err != nil {
		return fmt.Errorf("getting absolute path: %w", err)
	}

	// First, verify the certificate file exists
	if _, err := os.Stat(absPath); err != nil {
		return fmt.Errorf("certificate file not found: %w", err)
	}

	// Add to keychain
	cmd := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", absPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if it's a permission error
		if strings.Contains(string(output), "authorization") || strings.Contains(string(output), "permission") {
			// Retry with sudo
			sudoCmd := exec.Command("sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", absPath)
			if output, err = sudoCmd.CombinedOutput(); err != nil {
				return fmt.Errorf("installing CA certificate (with sudo): %s", string(output))
			}
		} else {
			return fmt.Errorf("installing CA certificate: %s", string(output))
		}
	}

	return nil
}

func (m *CertificateTrustManager) installAndTrustCALinux(certPath string) error {
	m.progress.StartProgress("Installing CA certificate")
	defer m.progress.CompleteProgress()

	// Get the absolute path
	absPath, err := filepath.Abs(certPath)
	if err != nil {
		return fmt.Errorf("getting absolute path: %w", err)
	}

	// First, verify the certificate file exists
	if _, err := os.Stat(absPath); err != nil {
		return fmt.Errorf("certificate file not found: %w", err)
	}

	// Copy to system CA directory
	destPath := "/usr/local/share/ca-certificates/certgen-ca.crt"
	cmd := exec.Command("sudo", "cp", absPath, destPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("copying CA certificate: %s", string(output))
	}

	// Update CA certificates
	cmd = exec.Command("sudo", "update-ca-certificates")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("updating CA certificates: %s", string(output))
	}

	return nil
}

func (m *CertificateTrustManager) installAndTrustCAWindows(certPath string) error {
	m.progress.StartProgress("Installing CA certificate")
	defer m.progress.CompleteProgress()

	// Get the absolute path
	absPath, err := filepath.Abs(certPath)
	if err != nil {
		return fmt.Errorf("getting absolute path: %w", err)
	}

	// First, verify the certificate file exists
	if _, err := os.Stat(absPath); err != nil {
		return fmt.Errorf("certificate file not found: %w", err)
	}

	// Import certificate to root store
	cmd := exec.Command("certutil", "-addstore", "-f", "ROOT", absPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Try with elevated privileges
		cmd = exec.Command("powershell", "Start-Process", "certutil",
			"-ArgumentList '-addstore -f ROOT \""+absPath+"\"'",
			"-Verb RunAs",
			"-Wait")
		if output, err = cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("installing CA certificate: %s", string(output))
		}
	}

	return nil
}
