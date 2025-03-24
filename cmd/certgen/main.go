package main

import (
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"certgen/internal/cert"
)

var rootCmd = &cobra.Command{
	Use:   "certgen",
	Short: "A certificate generation and management tool",
	Long: `A tool for generating and managing certificates with support for
different certificate classes and trust operations.

Certificate Classes:
  Class 1: Low-assurance certificates (email, personal use)
  Class 2: Medium-assurance certificates (organization validation)
  Class 3: High-assurance certificates (extended validation)`,
}

var helpCmd = &cobra.Command{
	Use:   "classes",
	Short: "Display information about certificate classes",
	Long:  "Display detailed information about the available certificate classes and their requirements",
	Run: func(cmd *cobra.Command, args []string) {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "\nCertificate Classes and Requirements:")
		fmt.Fprintln(w, "Class\tKey Size\tValidity\tUsage\tCA Path Length")
		fmt.Fprintln(w, "-----\t--------\t--------\t-----\t-------------")
		fmt.Fprintln(w, "1\t2048 bits\t5 years\tClient Auth, Email\t0 (No intermediates)")
		fmt.Fprintln(w, "2\t3072 bits\t3 years\tServer & Client Auth\t1 (One intermediate)")
		fmt.Fprintln(w, "3\t4096 bits\t2 years\tServer, Client & Code Signing\t2 (Two intermediates)")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Class Details:")
		fmt.Fprintln(w, "- Class 1: Low-assurance certificates for personal use and email protection")
		fmt.Fprintln(w, "- Class 2: Medium-assurance certificates with organization validation")
		fmt.Fprintln(w, "- Class 3: High-assurance certificates with extended validation and code signing capability")
		w.Flush()
	},
}

var completeHelpCmd = &cobra.Command{
	Use:   "help-all",
	Short: "Display complete help information",
	Long:  "Display comprehensive help information about all commands and their usage",
	Run: func(cmd *cobra.Command, args []string) {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

		// General Usage
		fmt.Fprintln(w, "\nCertGen - Certificate Generation and Management Tool")
		fmt.Fprintln(w, "==============================================")
		fmt.Fprintln(w, "\nUsage:")
		fmt.Fprintln(w, "  certgen [command] [flags]")

		// Available Commands
		fmt.Fprintln(w, "\nAvailable Commands:")
		fmt.Fprintln(w, "Command\tDescription\tUsage")
		fmt.Fprintln(w, "-------\t-----------\t-----")
		fmt.Fprintln(w, "ca\tGenerate a CA certificate\tcertgen ca [flags]")
		fmt.Fprintln(w, "cert\tGenerate a server/client certificate\tcertgen cert [flags]")
		fmt.Fprintln(w, "install\tInstall a certificate\tcertgen install [flags]")
		fmt.Fprintln(w, "trust\tTrust a CA certificate\tcertgen trust [flags]")
		fmt.Fprintln(w, "classes\tShow certificate class information\tcertgen classes")
		fmt.Fprintln(w, "help-all\tShow this help message\tcertgen help-all")

		// Common Flags
		fmt.Fprintln(w, "\nCommon Flags:")
		fmt.Fprintln(w, "Flag\tDescription\tDefault")
		fmt.Fprintln(w, "----\t-----------\t-------")
		fmt.Fprintln(w, "--class\tCertificate class (1-3)\t1")
		fmt.Fprintln(w, "--common-name\tCommon Name for the certificate\t-")
		fmt.Fprintln(w, "--org\tOrganization name\t-")
		fmt.Fprintln(w, "--country\tCountry code\t-")
		fmt.Fprintln(w, "--validity\tValidity period in days\tClass dependent")
		fmt.Fprintln(w, "--key-size\tKey size in bits\tClass dependent")
		fmt.Fprintln(w, "--output-dir\tOutput directory for certificates\t./certs")
		fmt.Fprintln(w, "--no-progress\tDisable progress display\tfalse")
		fmt.Fprintln(w, "--root\tGenerate a root certificate\tfalse")

		// Examples
		fmt.Fprintln(w, "\nExamples:")
		fmt.Fprintln(w, "1. Generate a Root CA certificate:")
		fmt.Fprintln(w, "   certgen ca --root --class 2 --common-name \"My Root CA\" --org \"My Company\"")
		fmt.Fprintln(w, "\n2. Generate an Intermediate CA certificate:")
		fmt.Fprintln(w, "   certgen ca --class 2 --common-name \"My Intermediate CA\" --org \"My Company\"")
		fmt.Fprintln(w, "\n3. Generate a server certificate:")
		fmt.Fprintln(w, "   certgen cert --class 2 --common-name \"example.com\" --org \"My Company\" --dns-names \"example.com,www.example.com\"")
		fmt.Fprintln(w, "\n4. Install and trust a CA certificate:")
		fmt.Fprintln(w, "   certgen install --cert path/to/ca.crt")
		fmt.Fprintln(w, "   certgen trust --cert path/to/ca.crt")

		// Additional Information
		fmt.Fprintln(w, "\nFor more information about certificate classes:")
		fmt.Fprintln(w, "  certgen classes")

		w.Flush()
	},
}

func parseClass(class string) (cert.CertificateClass, error) {
	classNum, err := strconv.Atoi(class)
	if err != nil {
		return 0, fmt.Errorf("invalid class number: %w", err)
	}
	if classNum < 1 || classNum > 3 {
		return 0, fmt.Errorf("class must be between 1 and 3")
	}
	return cert.CertificateClass(classNum), nil
}

func init() {
	rootCmd.AddCommand(helpCmd)
	rootCmd.AddCommand(completeHelpCmd)
}

// loadConfig loads a YAML configuration file into the provided config struct
func loadConfig(configFile string, config interface{}) error {
	if configFile == "" {
		return fmt.Errorf("configuration file is required")
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("reading config file: %w", err)
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return fmt.Errorf("parsing config file: %w", err)
	}

	return nil
}

func main() {
	var (
		configFile string
		noProgress bool
	)

	rootCmd := &cobra.Command{
		Use:   "certgen",
		Short: "A tool for generating and managing certificates",
		Long: `certgen is a tool for generating and managing certificates.
It supports generating CA certificates, server certificates, and signing certificates.`,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "Path to configuration file")
	rootCmd.PersistentFlags().BoolVar(&noProgress, "no-progress", false, "Disable progress display")

	// CA command
	caCmd := &cobra.Command{
		Use:   "ca",
		Short: "Generate a Certificate Authority certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			config := &cert.CAConfig{
				NoProgress: noProgress,
			}
			if err := loadConfig(configFile, config); err != nil {
				return err
			}
			_, err := cert.GenerateCA(config)
			return err
		},
	}

	// Certificate command
	certCmd := &cobra.Command{
		Use:   "cert",
		Short: "Generate a server or client certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			config := &cert.CertConfig{
				NoProgress: noProgress,
			}
			if err := loadConfig(configFile, config); err != nil {
				return err
			}
			return cert.GenerateCertificate(config)
		},
	}

	// Sign command
	signCmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign an existing certificate with a CA",
		RunE: func(cmd *cobra.Command, args []string) error {
			config := &cert.SignConfig{
				NoProgress: noProgress,
			}
			if err := loadConfig(configFile, config); err != nil {
				return err
			}
			return cert.SignCertificate(config)
		},
	}

	rootCmd.AddCommand(caCmd, certCmd, signCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
