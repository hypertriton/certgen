# CertGen - Certificate Generation and Management Tool

CertGen is a powerful command-line tool for generating and managing digital certificates with support for multiple certificate classes and trust operations. It simplifies the process of creating and managing certificates for various security levels and use cases.

## Features

- Support for three certificate classes with different security levels
- CA (Certificate Authority) certificate generation
- Server/Client certificate generation
- Certificate installation and trust management
- Progress tracking for operations
- Flexible configuration options

## Certificate Classes

CertGen supports three certificate classes, each with specific security requirements:

| Class | Key Size | Validity | Usage | CA Path Length |
|-------|----------|----------|-------|----------------|
| 1 | 2048 bits | 5 years | Client Auth, Email | 0 (No intermediates) |
| 2 | 3072 bits | 3 years | Server & Client Auth | 1 (One intermediate) |
| 3 | 4096 bits | 2 years | Server, Client & Code Signing | 2 (Two intermediates) |

### Class Details

- **Class 1**: Low-assurance certificates for personal use and email protection
- **Class 2**: Medium-assurance certificates with organization validation
- **Class 3**: High-assurance certificates with extended validation and code signing capability

## Installation

```bash
go install github.com/yourusername/certgen@latest
```

## Usage

### Basic Command Structure

```bash
certgen [command] [flags]
```

### Available Commands

- `ca`: Generate a CA certificate
- `cert`: Generate a server/client certificate
- `install`: Install a certificate
- `trust`: Trust a CA certificate
- `classes`: Show certificate class information
- `help-all`: Show comprehensive help information

### Common Flags

| Flag | Description | Default |
|------|-------------|---------|
| --class | Certificate class (1-3) | 1 |
| --common-name | Common Name for the certificate | - |
| --org | Organization name | - |
| --country | Country code | - |
| --validity | Validity period in days | Class dependent |
| --key-size | Key size in bits | Class dependent |
| --output-dir | Output directory for certificates | ./certs |
| --no-progress | Disable progress display | false |

## Examples

### 1. Generate a Class 1 CA Certificate

```bash
certgen ca --class 1 --common-name "My Root CA" --org "My Company"
```

### 2. Generate a Class 2 Server Certificate

```bash
certgen cert --class 2 --common-name "example.com" --org "My Company" --dns-names "example.com,www.example.com"
```

### 3. Install and Trust a CA Certificate

```bash
certgen install --cert path/to/ca.crt
certgen trust --cert path/to/ca.crt
```

## Getting Help

For general help:
```bash
certgen --help
```

For detailed information about certificate classes:
```bash
certgen classes
```

For comprehensive documentation:
```bash
certgen help-all
```

## Security Considerations

- Choose the appropriate certificate class based on your security requirements
- Keep CA private keys secure and backed up
- Follow industry best practices for key sizes and validity periods
- Regularly review and update certificates before expiration

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 