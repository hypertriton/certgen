# CertGen - Certificate Generation and Management Tool

CertGen is a powerful command-line tool for generating and managing certificates with support for different certificate classes and trust operations. It provides a simple and secure way to create and manage your certificate infrastructure.

## Features

- Generate CA certificates (Root and Intermediate)
- Generate server and client certificates
- Support for different certificate classes (1-3)
- Certificate signing capabilities
- Certificate installation and trust management
- Progress tracking for long operations
- YAML-based configuration
- Comprehensive help and documentation

## Installation

```bash
go install github.com/hypertriton/certgen@latest
```

## Usage

CertGen provides several commands for different certificate operations:

### Generate a CA Certificate

```bash
certgen ca -c config/ca.yaml
```

### Generate a Server/Client Certificate

```bash
certgen cert -c config/cert.yaml
```

### Sign an Existing Certificate

```bash
certgen sign -c config/sign.yaml
```

### Show Certificate Class Information

```bash
certgen classes
```

### Show Complete Help

```bash
certgen help-all
```

## Certificate Classes

CertGen supports three certificate classes with different security levels and requirements:

1. **Class 1**: Low-assurance certificates
   - Minimum key size: 2048 bits
   - Maximum validity: 5 years
   - Usage: Client authentication, email protection
   - No intermediate CAs allowed

2. **Class 2**: Medium-assurance certificates
   - Minimum key size: 3072 bits
   - Maximum validity: 3 years
   - Usage: Server and client authentication
   - One level of intermediate CAs allowed

3. **Class 3**: High-assurance certificates
   - Minimum key size: 4096 bits
   - Maximum validity: 2 years
   - Usage: Server, client, and code signing
   - Two levels of intermediate CAs allowed

## Configuration Files

CertGen uses YAML configuration files for different operations:

### CA Configuration (config/ca.yaml)

```yaml
# Certificate Authority Configuration
# This file configures settings for generating a CA certificate

# Certificate type (root or intermediate)
type: "root"

# Certificate class (1-3)
class: 2

# Basic Information
commonName: "My Root CA"
organization: "My Company"
organizationalUnit: "IT Department"
country: "US"
province: "California"
locality: "San Francisco"

# Validity and Key Size
validityDays: 3650  # 10 years
keySize: 4096       # Minimum for root certificates

# Output directory
outputDir: "certs"

# Optional: Disable progress display
# noProgress: false
```

### Certificate Configuration (config/cert.yaml)

```yaml
# Server/Client Certificate Configuration
# This file configures settings for generating a server or client certificate

# Certificate class (1-3)
class: 2

# Basic Information
commonName: "example.com"
organization: "My Company"
organizationalUnit: "IT Department"
country: "US"
province: "California"
locality: "San Francisco"

# Validity and Key Size
validityDays: 365  # 1 year
keySize: 2048      # Minimum for Class 1

# DNS Names (for server certificates)
dnsNames:
  - "example.com"
  - "www.example.com"

# CA Information
caCert: "certs/ca.crt"
caKey: "certs/ca.key"

# Output directory
outputDir: "certs"

# Optional: Disable progress display
# noProgress: false
```

### Sign Configuration (config/sign.yaml)

```yaml
# Certificate Signing Configuration
# This file configures settings for signing an existing certificate with a CA

# Path to the certificate to be signed
certPath: "certs/cert.crt"

# Path to the certificate's private key
keyPath: "certs/cert.key"

# Path to the CA certificate
caCertPath: "certs/ca.crt"

# Path to the CA private key
caKeyPath: "certs/ca.key"

# Output directory for the signed certificate
outputDir: "certs"

# Optional: Disable progress display
# noProgress: false
```

## Common Flags

- `-c, --config`: Path to configuration file (required)
- `--no-progress`: Disable progress display

## Examples

1. Generate a Root CA certificate:
```bash
certgen ca -c config/ca.yaml
```

2. Generate a server certificate:
```bash
certgen cert -c config/cert.yaml
```

3. Sign an existing certificate:
```bash
certgen sign -c config/sign.yaml
```

4. Show certificate class information:
```bash
certgen classes
```

## Security Considerations

- Root certificates should be Class 2 or higher
- Root certificates must use at least 4096-bit keys
- Root certificates should have longer validity periods (5+ years)
- Private keys are stored with appropriate permissions (0600)
- Certificates are stored with standard permissions (0644)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 