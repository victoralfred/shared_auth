package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"
)

// GenerateTestToken generates a test JWT token (for testing only)
func GenerateTestToken(privateKey *rsa.PrivateKey, claims *Claims) (string, error) {
	// Create header
	header := Header{
		Algorithm: "RS256",
		Type:      "JWT",
		KeyID:     claims.KeyID,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	// Encode to base64url
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Create signature
	message := headerB64 + "." + claimsB64
	hash := sha256.Sum256([]byte(message))

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}

	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return message + "." + signatureB64, nil
}

// CreateTestClaims creates test claims with default values
func CreateTestClaims() *Claims {
	now := time.Now()
	return &Claims{
		Subject:   "test-user-123",
		Issuer:    "kubemanager",
		Audience:  "test-service",
		ExpiresAt: now.Add(15 * time.Minute).Unix(),
		NotBefore: now.Unix(),
		IssuedAt:  now.Unix(),
		UserID:    "test-user-123",
		TenantID:  "test-tenant-456",
		Email:     "test@example.com",
		Roles:     []string{"user", "manager"},
		Permissions: map[string][]string{
			"orders":   {"create", "read", "update"},
			"products": {"read"},
			"invoices": {"*"},
		},
		TokenType: "access",
		KeyID:     "key-1",
	}
}

// CreateExpiredClaims creates claims that are already expired
func CreateExpiredClaims() *Claims {
	claims := CreateTestClaims()
	claims.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix()
	return claims
}

// CreateNotYetValidClaims creates claims that are not yet valid
func CreateNotYetValidClaims() *Claims {
	claims := CreateTestClaims()
	claims.NotBefore = time.Now().Add(1 * time.Hour).Unix()
	return claims
}
