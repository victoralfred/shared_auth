// Package jwt provides stateless JWT token verification for Go microservices.
//
// This package implements cryptographic verification of JWT tokens without
// requiring database queries or external service calls. All verification is
// done locally using RSA public key cryptography.
//
// # Features
//
//   - Stateless token verification using RSA signatures
//   - Support for access and refresh tokens
//   - Embedded user permissions and roles in claims
//   - Multi-tenant support with tenant ID in claims
//   - Standard JWT claims validation (expiry, issuer, audience)
//   - Helper methods for permission and role checks
//
// # Quick Start
//
// Create a verifier and verify tokens:
//
//	import (
//	    "github.com/victoralfred/shared_auth/jwt"
//	    "github.com/victoralfred/shared_auth/crypto"
//	)
//
//	// Load public key
//	publicKey, err := crypto.LoadPublicKeyFromFile("/path/to/jwt_public.pem")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Create verifier
//	verifier := jwt.NewVerifier(publicKey, "your-issuer", "your-audience")
//
//	// Verify token
//	claims, err := verifier.VerifyToken(tokenString)
//	if err != nil {
//	    // Handle invalid token
//	    return
//	}
//
//	// Use claims
//	userID := claims.UserID
//	tenantID := claims.TenantID
//
//	// Check permissions
//	if claims.HasPermission("orders", "create") {
//	    // User can create orders
//	}
//
//	// Check roles
//	if claims.HasRole("admin") {
//	    // User is admin
//	}
//
// # Token Types
//
// The package supports two token types:
//
//	// Access tokens (short-lived, used for API requests)
//	claims, err := verifier.VerifyAccessToken(tokenString)
//
//	// Refresh tokens (long-lived, used to get new access tokens)
//	claims, err := verifier.VerifyRefreshToken(tokenString)
//
// # Claims Structure
//
// JWT claims contain both standard and custom fields:
//
//	type Claims struct {
//	    // Standard JWT claims
//	    Subject   string  // User ID
//	    Issuer    string  // Token issuer
//	    Audience  string  // Intended audience
//	    ExpiresAt int64   // Expiration timestamp
//	    NotBefore int64   // Valid from timestamp
//	    IssuedAt  int64   // Issue timestamp
//
//	    // Custom claims
//	    UserID      string              // User identifier
//	    TenantID    string              // Tenant identifier
//	    Email       string              // User email
//	    Roles       []string            // User roles
//	    Permissions map[string][]string // Resource -> Actions mapping
//	    TokenType   string              // "access" or "refresh"
//	}
//
// # Permission Checks
//
// Claims provide convenient methods for checking permissions:
//
//	// Single permission
//	canCreate := claims.HasPermission("orders", "create")
//
//	// Any of multiple actions
//	canReadOrWrite := claims.HasAnyPermission("orders", []string{"read", "write"})
//
//	// All actions required
//	hasFullAccess := claims.HasAllPermissions("orders", []string{"read", "create", "update"})
//
//	// Get all actions for a resource
//	actions := claims.GetPermissionsForResource("orders")  // ["read", "create"]
//
//	// Get all resources user has access to
//	resources := claims.GetAllResources()  // ["orders", "customers", "products"]
//
// # Role Checks
//
// Claims also provide role checking methods:
//
//	// Single role
//	isAdmin := claims.HasRole("admin")
//
//	// Any of multiple roles
//	isManagerOrAdmin := claims.HasAnyRole([]string{"manager", "admin"})
//
//	// Admin check (checks for "admin" or "super_admin")
//	isSuperUser := claims.IsAdmin()
//
// # Error Handling
//
// The package defines specific error types for different failure scenarios:
//
//	import "errors"
//
//	claims, err := verifier.VerifyToken(tokenString)
//	if err != nil {
//	    switch {
//	    case errors.Is(err, jwt.ErrInvalidToken):
//	        // Token is malformed or invalid
//	    case errors.Is(err, jwt.ErrExpiredToken):
//	        // Token has expired
//	    case errors.Is(err, jwt.ErrInvalidSignature):
//	        // Signature verification failed
//	    case errors.Is(err, jwt.ErrInvalidIssuer):
//	        // Issuer doesn't match expected value
//	    case errors.Is(err, jwt.ErrInvalidAudience):
//	        // Audience doesn't match expected value
//	    case errors.Is(err, jwt.ErrInvalidTokenType):
//	        // Token type doesn't match (e.g., refresh token when access expected)
//	    }
//	}
//
// # Multi-Tenant Usage
//
// The package fully supports multi-tenant applications:
//
//	claims, _ := verifier.VerifyToken(tokenString)
//
//	// Tenant is embedded in the token
//	tenantID := claims.TenantID  // "tenant-123"
//
//	// Use tenant ID for database queries, authorization, etc.
//	orders := db.GetOrders(claims.UserID, claims.TenantID)
//
// # Integration with Middleware
//
// Use with the middleware package for HTTP authentication:
//
//	import (
//	    "github.com/gin-gonic/gin"
//	    "github.com/victoralfred/shared_auth/middleware"
//	)
//
//	router := gin.Default()
//	router.Use(middleware.AuthMiddleware(verifier))
//
//	router.GET("/profile", func(c *gin.Context) {
//	    // Get claims from context
//	    claims, _ := c.Get("claims")
//	    jwtClaims := claims.(*jwt.Claims)
//
//	    c.JSON(200, gin.H{
//	        "user_id": jwtClaims.UserID,
//	        "email":   jwtClaims.Email,
//	    })
//	})
//
// # Security Considerations
//
//   - Always verify tokens on every request (stateless verification is fast)
//   - Ensure your public key is loaded securely (from Vault, secure file, etc.)
//   - Use appropriate issuer and audience values to prevent token replay attacks
//   - Implement token revocation using a cache/blacklist if needed
//   - Use short expiration times for access tokens (e.g., 15 minutes)
//   - Rotate signing keys periodically
//
// # Performance
//
// Token verification is purely cryptographic and very fast:
//   - No database queries required
//   - No network calls required
//   - Suitable for high-throughput applications
//   - O(1) complexity for verification
//
// Typical verification time: < 1ms per token
package jwt

// Verifier defines the interface for JWT token verification.
//
// This is the public contract that consuming services depend on.
// The implementation details are private and can change without breaking clients.
//
// Create a verifier using the factory function:
//
//	verifier := jwt.NewVerifier(publicKey, "kubemanager", "my-service")
//
// Then use it to verify tokens:
//
//	claims, err := verifier.VerifyToken(tokenString)
type Verifier interface {
	// VerifyToken verifies and parses a JWT token.
	//
	// This method performs full cryptographic verification including:
	//   - Signature validation using RSA public key
	//   - Expiration time check
	//   - Not-before time check
	//   - Issuer validation
	//   - Audience validation
	//
	// Returns the parsed claims if valid, or an error if verification fails.
	VerifyToken(tokenString string) (*Claims, error)

	// VerifyAccessToken verifies that the token is specifically an access token.
	//
	// This performs all the same checks as VerifyToken, plus an additional check
	// that the token_type claim is "access". Use this when you specifically need
	// an access token and want to reject refresh tokens.
	//
	// Returns the parsed claims if valid, or an error if verification fails or
	// if the token is not an access token.
	VerifyAccessToken(tokenString string) (*Claims, error)

	// VerifyRefreshToken verifies that the token is specifically a refresh token.
	//
	// This performs all the same checks as VerifyToken, plus an additional check
	// that the token_type claim is "refresh". Use this when you specifically need
	// a refresh token and want to reject access tokens.
	//
	// Returns the parsed claims if valid, or an error if verification fails or
	// if the token is not a refresh token.
	VerifyRefreshToken(tokenString string) (*Claims, error)
}
