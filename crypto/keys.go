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
