package jwt

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// Verifier provides stateless JWT verification
// NO database dependencies - pure cryptographic verification
type Verifier struct {
	publicKey *rsa.PublicKey
	issuer    string
	audience  string
}

// NewVerifier creates a JWT verifier with public key
func NewVerifier(publicKey *rsa.PublicKey, issuer, audience string) *Verifier {
	return &Verifier{
		publicKey: publicKey,
		issuer:    issuer,
		audience:  audience,
	}
}

// VerifyToken verifies JWT signature and standard claims
// Does NOT check revocation status or database
func (v *Verifier) VerifyToken(tokenString string) (*Claims, error) {
	// Split token into parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedToken
	}

	// Decode header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformedToken
	}

	var header Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, ErrMalformedToken
	}

	// Verify algorithm
	if header.Algorithm != "RS256" {
		return nil, ErrInvalidAlgorithm
	}

	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformedToken
	}

	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, ErrMalformedToken
	}

	// Verify signature
	message := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidSignature
	}

	if err := v.verifySignature([]byte(message), signature); err != nil {
		return nil, ErrInvalidSignature
	}

	// Validate claims
	if err := v.validateClaims(&claims); err != nil {
		return nil, err
	}

	return &claims, nil
}

// verifySignature verifies RSA signature
func (v *Verifier) verifySignature(data []byte, signature []byte) error {
	hash := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(v.publicKey, crypto.SHA256, hash[:], signature)
}

// validateClaims validates standard JWT claims
func (v *Verifier) validateClaims(claims *Claims) error {
	now := time.Now().Unix()

	// Check expiration
	if claims.ExpiresAt < now {
		return ErrTokenExpired
	}

	// Check not before
	if claims.NotBefore > now {
		return ErrTokenNotYetValid
	}

	// Check issuer
	if v.issuer != "" && claims.Issuer != v.issuer {
		return ErrInvalidIssuer
	}

	// Check audience
	if v.audience != "" && claims.Audience != v.audience {
		return ErrInvalidAudience
	}

	return nil
}

// VerifyRefreshToken specifically for refresh tokens
func (v *Verifier) VerifyRefreshToken(tokenString string) (*Claims, error) {
	claims, err := v.VerifyToken(tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != "refresh" {
		return nil, ErrInvalidTokenType
	}

	return claims, nil
}

// VerifyAccessToken specifically for access tokens
func (v *Verifier) VerifyAccessToken(tokenString string) (*Claims, error) {
	claims, err := v.VerifyToken(tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != "access" {
		return nil, ErrInvalidTokenType
	}

	return claims, nil
}

// ExtractClaimsWithoutVerifying extracts claims without verification
// WARNING: Only use for debugging! Never trust unverified claims!
func ExtractClaimsWithoutVerifying(tokenString string) (*Claims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedToken
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformedToken
	}

	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, ErrMalformedToken
	}

	return &claims, nil
}
