package jwt

// Verifier defines the interface for JWT token verification.
//
// This is the public contract that consuming services depend on.
// The implementation details are private and can change without breaking clients.
//
// Usage:
//
//	// Service creates verifier using factory function
//	verifier := jwt.NewVerifier(publicKey, "kubemanager", "my-service")
//
//	// Use through interface
//	claims, err := verifier.VerifyToken(tokenString)
type Verifier interface {
	// VerifyToken verifies and parses a JWT token
	VerifyToken(tokenString string) (*Claims, error)

	// VerifyAccessToken verifies that the token is specifically an access token
	VerifyAccessToken(tokenString string) (*Claims, error)

	// VerifyRefreshToken verifies that the token is specifically a refresh token
	VerifyRefreshToken(tokenString string) (*Claims, error)
}
