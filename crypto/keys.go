// Package crypto provides utilities for loading and parsing RSA cryptographic keys.
//
// This package helps you load JWT signing keys from various sources (files,
// environment variables, or raw PEM data) for use with the jwt package.
//
// # Features
//
//   - Load RSA public keys from PEM files
//   - Load RSA public keys from environment variables
//   - Parse RSA public keys from PEM-encoded bytes
//   - Load RSA private keys from PEM files (for testing or token generation)
//   - Support for both PKCS1 and PKCS8 key formats
//   - Clear error messages for debugging
//
// # Quick Start
//
// Load a public key for JWT verification:
//
//	import (
//	    "github.com/victoralfred/shared_auth/crypto"
//	    "github.com/victoralfred/shared_auth/jwt"
//	)
//
//	// From file
//	publicKey, err := crypto.LoadPublicKeyFromFile("/path/to/jwt_public.pem")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Create verifier
//	verifier := jwt.NewVerifier(publicKey, "your-issuer", "your-audience")
//
// # Loading from Files
//
// Load RSA keys from PEM files:
//
//	// Public key
//	publicKey, err := crypto.LoadPublicKeyFromFile("/etc/secrets/jwt_public.pem")
//	if err != nil {
//	    log.Fatalf("Failed to load public key: %v", err)
//	}
//
//	// Private key (for testing or token generation services)
//	privateKey, err := crypto.LoadPrivateKeyFromFile("/etc/secrets/jwt_private.pem")
//	if err != nil {
//	    log.Fatalf("Failed to load private key: %v", err)
//	}
//
// # Loading from Environment Variables
//
// Load keys from environment variables (useful for containerized deployments):
//
//	// Public key
//	publicKey, err := crypto.LoadPublicKeyFromEnv("JWT_PUBLIC_KEY")
//	if err != nil {
//	    log.Fatalf("Failed to load public key from env: %v", err)
//	}
//
//	// Private key
//	privateKey, err := crypto.LoadPrivateKeyFromEnv("JWT_PRIVATE_KEY")
//	if err != nil {
//	    log.Fatalf("Failed to load private key from env: %v", err)
//	}
//
// Set the environment variable with the PEM-encoded key:
//
//	export JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
//	MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
//	-----END PUBLIC KEY-----"
//
// # Loading from Vault or Secrets Manager
//
// Integrate with your secrets management system:
//
//	import (
//	    "context"
//	    "github.com/victoralfred/shared_auth/crypto"
//	    "your-company/vault"  // Your Vault client
//	)
//
//	// Get key from Vault
//	vaultClient, _ := vault.NewClient(vaultConfig)
//	secretData, _ := vaultClient.GetSecret(context.Background(), "jwt/public_key")
//	publicKeyPEM := secretData["public_key"].(string)
//
//	// Parse the PEM data
//	publicKey, err := crypto.ParsePublicKey([]byte(publicKeyPEM))
//	if err != nil {
//	    log.Fatalf("Failed to parse public key: %v", err)
//	}
//
// # Parsing Raw PEM Data
//
// If you already have PEM-encoded key data as bytes:
//
//	pemData := []byte(`-----BEGIN PUBLIC KEY-----
//	MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
//	-----END PUBLIC KEY-----`)
//
//	publicKey, err := crypto.ParsePublicKey(pemData)
//	if err != nil {
//	    log.Fatalf("Failed to parse public key: %v", err)
//	}
//
// # PEM Format
//
// Public keys should be in PKIX format (standard for public keys):
//
//	-----BEGIN PUBLIC KEY-----
//	MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
//	4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
//	+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
//	kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
//	0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
//	cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
//	mwIDAQAB
//	-----END PUBLIC KEY-----
//
// Private keys support both PKCS1 and PKCS8 formats:
//
//	// PKCS1 format
//	-----BEGIN RSA PRIVATE KEY-----
//	...
//	-----END RSA PRIVATE KEY-----
//
//	// PKCS8 format (also supported)
//	-----BEGIN PRIVATE KEY-----
//	...
//	-----END PRIVATE KEY-----
//
// # Generating Keys
//
// Generate RSA key pairs for testing using OpenSSL:
//
//	# Generate private key
//	openssl genrsa -out jwt_private.pem 2048
//
//	# Extract public key
//	openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem
//
// # Error Handling
//
// All functions return descriptive errors:
//
//	publicKey, err := crypto.LoadPublicKeyFromFile("/path/to/key.pem")
//	if err != nil {
//	    switch {
//	    case os.IsNotExist(err):
//	        log.Fatal("Key file not found")
//	    default:
//	        log.Fatalf("Failed to load key: %v", err)
//	    }
//	}
//
// Common errors:
//   - "failed to parse PEM block" - Invalid PEM format
//   - "not an RSA public key" - Key is not RSA (e.g., ECDSA)
//   - "environment variable not set" - Env var is empty or missing
//   - File system errors (permission denied, not found, etc.)
//
// # Security Considerations
//
//   - Never commit private keys to version control
//   - Store keys in secure locations (Vault, AWS Secrets Manager, etc.)
//   - Use appropriate file permissions (600 for private keys)
//   - Rotate keys periodically
//   - Use strong key sizes (minimum 2048 bits, preferably 4096)
//
// # Integration Example
//
// Complete example loading keys and creating JWT verifier:
//
//	package main
//
//	import (
//	    "log"
//	    "os"
//
//	    "github.com/victoralfred/shared_auth/crypto"
//	    "github.com/victoralfred/shared_auth/jwt"
//	)
//
//	func main() {
//	    var publicKey *rsa.PublicKey
//	    var err error
//
//	    // Try loading from file first
//	    keyPath := os.Getenv("JWT_PUBLIC_KEY_PATH")
//	    if keyPath != "" {
//	        publicKey, err = crypto.LoadPublicKeyFromFile(keyPath)
//	    } else {
//	        // Fallback to environment variable
//	        publicKey, err = crypto.LoadPublicKeyFromEnv("JWT_PUBLIC_KEY")
//	    }
//
//	    if err != nil {
//	        log.Fatalf("Failed to load JWT public key: %v", err)
//	    }
//
//	    // Create verifier
//	    verifier := jwt.NewVerifier(publicKey, "your-issuer", "your-audience")
//
//	    // Use verifier...
//	}
//
// # Best Practices
//
//   - Load keys once at application startup, not per request
//   - Cache loaded keys in memory
//   - Use Vault or similar for production key management
//   - Implement key rotation without downtime
//   - Monitor key expiration dates
//   - Have a key rollover plan
package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

// LoadPublicKeyFromFile loads RSA public key from PEM file
func LoadPublicKeyFromFile(path string) (*rsa.PublicKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return ParsePublicKey(keyData)
}

// ParsePublicKey parses RSA public key from PEM data
func ParsePublicKey(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaKey, nil
}

// LoadPublicKeyFromEnv loads public key from environment variable
func LoadPublicKeyFromEnv(envVar string) (*rsa.PublicKey, error) {
	pemData := os.Getenv(envVar)
	if pemData == "" {
		return nil, errors.New("environment variable not set")
	}

	return ParsePublicKey([]byte(pemData))
}

// LoadPrivateKeyFromFile loads RSA private key from PEM file
func LoadPrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return ParsePrivateKey(keyData)
}

// ParsePrivateKey parses RSA private key from PEM data
func ParsePrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		rsaKey, ok := privKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA private key")
		}
		return rsaKey, nil
	}

	return priv, nil
}

// LoadPrivateKeyFromEnv loads private key from environment variable
func LoadPrivateKeyFromEnv(envVar string) (*rsa.PrivateKey, error) {
	pemData := os.Getenv(envVar)
	if pemData == "" {
		return nil, errors.New("environment variable not set")
	}

	return ParsePrivateKey([]byte(pemData))
}
