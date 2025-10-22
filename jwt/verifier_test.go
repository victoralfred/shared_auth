package jwt

import (
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/victoralfred/shared_auth/crypto"
)

func setupTestKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := crypto.LoadPrivateKeyFromFile("../testdata/jwt-private.pem")
	require.NoError(t, err)

	publicKey, err := crypto.LoadPublicKeyFromFile("../testdata/jwt-public.pem")
	require.NoError(t, err)

	return privateKey, publicKey
}

func TestVerifyToken_ValidToken(t *testing.T) {
	privateKey, publicKey := setupTestKeys(t)

	verifier := NewVerifier(publicKey, "kubemanager", "test-service")

	// Generate valid token
	claims := CreateTestClaims()
	token, err := GenerateTestToken(privateKey, claims)
	require.NoError(t, err)

	// Verify token
	verifiedClaims, err := verifier.VerifyToken(token)
	require.NoError(t, err)
	assert.NotNil(t, verifiedClaims)

	// Verify claims content
	assert.Equal(t, claims.UserID, verifiedClaims.UserID)
	assert.Equal(t, claims.TenantID, verifiedClaims.TenantID)
	assert.Equal(t, claims.Email, verifiedClaims.Email)
	assert.Equal(t, claims.Roles, verifiedClaims.Roles)
	assert.Equal(t, claims.TokenType, verifiedClaims.TokenType)
	assert.Equal(t, claims.Permissions, verifiedClaims.Permissions)
}

func TestVerifyToken_ExpiredToken(t *testing.T) {
	privateKey, publicKey := setupTestKeys(t)

	verifier := NewVerifier(publicKey, "kubemanager", "test-service")

	// Generate expired token
	claims := CreateExpiredClaims()
	token, err := GenerateTestToken(privateKey, claims)
	require.NoError(t, err)

	// Verify token - should fail
	verifiedClaims, err := verifier.VerifyToken(token)
	assert.Error(t, err)
	assert.Equal(t, ErrTokenExpired, err)
	assert.Nil(t, verifiedClaims)
}

func TestVerifyToken_NotYetValid(t *testing.T) {
	privateKey, publicKey := setupTestKeys(t)

	verifier := NewVerifier(publicKey, "kubemanager", "test-service")

	// Generate not-yet-valid token
	claims := CreateNotYetValidClaims()
	token, err := GenerateTestToken(privateKey, claims)
	require.NoError(t, err)

	// Verify token - should fail
	verifiedClaims, err := verifier.VerifyToken(token)
	assert.Error(t, err)
	assert.Equal(t, ErrTokenNotYetValid, err)
	assert.Nil(t, verifiedClaims)
}

func TestVerifyToken_InvalidIssuer(t *testing.T) {
	privateKey, publicKey := setupTestKeys(t)

	verifier := NewVerifier(publicKey, "kubemanager", "test-service")

	// Generate token with wrong issuer
	claims := CreateTestClaims()
	claims.Issuer = "wrong-issuer"
	token, err := GenerateTestToken(privateKey, claims)
	require.NoError(t, err)

	// Verify token - should fail
	verifiedClaims, err := verifier.VerifyToken(token)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidIssuer, err)
	assert.Nil(t, verifiedClaims)
}

func TestVerifyToken_InvalidAudience(t *testing.T) {
	privateKey, publicKey := setupTestKeys(t)

	verifier := NewVerifier(publicKey, "kubemanager", "test-service")

	// Generate token with wrong audience
	claims := CreateTestClaims()
	claims.Audience = "wrong-audience"
	token, err := GenerateTestToken(privateKey, claims)
	require.NoError(t, err)

	// Verify token - should fail
	verifiedClaims, err := verifier.VerifyToken(token)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidAudience, err)
	assert.Nil(t, verifiedClaims)
}

func TestVerifyToken_MalformedToken(t *testing.T) {
	_, publicKey := setupTestKeys(t)

	verifier := NewVerifier(publicKey, "kubemanager", "test-service")

	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "empty token",
			token: "",
		},
		{
			name:  "invalid format - no dots",
			token: "invalidtoken",
		},
		{
			name:  "invalid format - one dot",
			token: "header.payload",
		},
		{
			name:  "invalid format - too many dots",
			token: "header.payload.signature.extra",
		},
		{
			name:  "invalid base64",
			token: "!!!.!!!.!!!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifiedClaims, err := verifier.VerifyToken(tt.token)
			assert.Error(t, err)
			assert.Nil(t, verifiedClaims)
		})
	}
}

func TestVerifyToken_InvalidSignature(t *testing.T) {
	privateKey, publicKey := setupTestKeys(t)

	verifier := NewVerifier(publicKey, "kubemanager", "test-service")

	// Generate valid token
	claims := CreateTestClaims()
	token, err := GenerateTestToken(privateKey, claims)
	require.NoError(t, err)

	// Tamper with signature
	tamperedToken := token[:len(token)-10] + "xxxxxxxxxx"

	// Verify token - should fail
	verifiedClaims, err := verifier.VerifyToken(tamperedToken)
	assert.Error(t, err)
	assert.Nil(t, verifiedClaims)
}

func TestVerifyRefreshToken(t *testing.T) {
	privateKey, publicKey := setupTestKeys(t)

	verifier := NewVerifier(publicKey, "kubemanager", "test-service")

	// Generate refresh token
	claims := CreateTestClaims()
	claims.TokenType = "refresh"
	token, err := GenerateTestToken(privateKey, claims)
	require.NoError(t, err)

	// Verify as refresh token
	verifiedClaims, err := verifier.VerifyRefreshToken(token)
	require.NoError(t, err)
	assert.NotNil(t, verifiedClaims)
	assert.Equal(t, "refresh", verifiedClaims.TokenType)
}

func TestVerifyRefreshToken_WrongTokenType(t *testing.T) {
	privateKey, publicKey := setupTestKeys(t)

	verifier := NewVerifier(publicKey, "kubemanager", "test-service")

	// Generate access token (not refresh)
	claims := CreateTestClaims()
	claims.TokenType = "access"
	token, err := GenerateTestToken(privateKey, claims)
	require.NoError(t, err)

	// Try to verify as refresh token - should fail
	verifiedClaims, err := verifier.VerifyRefreshToken(token)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidTokenType, err)
	assert.Nil(t, verifiedClaims)
}

func TestVerifyAccessToken(t *testing.T) {
	privateKey, publicKey := setupTestKeys(t)

	verifier := NewVerifier(publicKey, "kubemanager", "test-service")

	// Generate access token
	claims := CreateTestClaims()
	claims.TokenType = "access"
	token, err := GenerateTestToken(privateKey, claims)
	require.NoError(t, err)

	// Verify as access token
	verifiedClaims, err := verifier.VerifyAccessToken(token)
	require.NoError(t, err)
	assert.NotNil(t, verifiedClaims)
	assert.Equal(t, "access", verifiedClaims.TokenType)
}

func TestExtractClaimsWithoutVerifying(t *testing.T) {
	privateKey, _ := setupTestKeys(t)

	claims := CreateTestClaims()
	token, err := GenerateTestToken(privateKey, claims)
	require.NoError(t, err)

	// Extract without verifying
	extractedClaims, err := ExtractClaimsWithoutVerifying(token)
	require.NoError(t, err)
	assert.NotNil(t, extractedClaims)

	assert.Equal(t, claims.UserID, extractedClaims.UserID)
	assert.Equal(t, claims.Email, extractedClaims.Email)
	assert.Equal(t, claims.TenantID, extractedClaims.TenantID)
}

func TestVerifierWithRealWorldScenario(t *testing.T) {
	privateKey, publicKey := setupTestKeys(t)

	verifier := NewVerifier(publicKey, "kubemanager", "order-service")

	// Simulate real user from e-commerce system
	claims := &Claims{
		Subject:   "user-7890",
		Issuer:    "kubemanager",
		Audience:  "order-service",
		ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
		NotBefore: time.Now().Unix(),
		IssuedAt:  time.Now().Unix(),
		UserID:    "user-7890",
		TenantID:  "company-acme",
		Email:     "john.doe@acme.com",
		Roles:     []string{"customer", "premium_member"},
		Permissions: map[string][]string{
			"orders":   {"create", "read", "update", "cancel"},
			"products": {"read", "review"},
			"cart":     {"*"},
			"wishlist": {"*"},
			"profile":  {"read", "update"},
		},
		TokenType:   "access",
		DisplayName: "John Doe",
		AvatarURL:   "https://cdn.acme.com/avatars/user-7890.jpg",
	}

	token, err := GenerateTestToken(privateKey, claims)
	require.NoError(t, err)

	// Verify token
	verifiedClaims, err := verifier.VerifyToken(token)
	require.NoError(t, err)

	// Test permission checks
	assert.True(t, verifiedClaims.HasPermission("orders", "create"))
	assert.True(t, verifiedClaims.HasPermission("orders", "cancel"))
	assert.True(t, verifiedClaims.HasPermission("cart", "delete")) // wildcard
	assert.False(t, verifiedClaims.HasPermission("orders", "delete"))
	assert.False(t, verifiedClaims.HasPermission("admin", "access"))

	// Test role checks
	assert.True(t, verifiedClaims.HasRole("customer"))
	assert.True(t, verifiedClaims.HasRole("premium_member"))
	assert.False(t, verifiedClaims.HasRole("admin"))

	// Test admin check
	assert.False(t, verifiedClaims.IsAdmin())
}
