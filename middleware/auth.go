package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/victoralfred/shared_auth/jwt"
)

// AuthMiddleware creates Gin middleware for JWT authentication
func AuthMiddleware(verifier *jwt.Verifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(401, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Remove "Bearer " prefix
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader {
			c.JSON(401, gin.H{"error": "Invalid authorization format"})
			c.Abort()
			return
		}

		// Verify token
		claims, err := verifier.VerifyToken(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid token", "details": err.Error()})
			c.Abort()
			return
		}

		// Store claims in context
		c.Set("user_id", claims.UserID)
		c.Set("tenant_id", claims.TenantID)
		c.Set("email", claims.Email)
		c.Set("roles", claims.Roles)
		c.Set("permissions", claims.Permissions)
		c.Set("claims", claims)

		c.Next()
	}
}

// OptionalAuthMiddleware provides optional authentication
func OptionalAuthMiddleware(verifier *jwt.Verifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := verifier.VerifyToken(token)
		if err == nil {
			c.Set("user_id", claims.UserID)
			c.Set("tenant_id", claims.TenantID)
			c.Set("email", claims.Email)
			c.Set("roles", claims.Roles)
			c.Set("permissions", claims.Permissions)
			c.Set("claims", claims)
		}

		c.Next()
	}
}

// RequirePermission creates middleware to check specific permission
func RequirePermission(resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, exists := c.Get("claims")
		if !exists {
			c.JSON(401, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		jwtClaims := claims.(*jwt.Claims)
		if !jwtClaims.HasPermission(resource, action) {
			c.JSON(403, gin.H{
				"error":   "Forbidden",
				"details": "Missing required permission",
				"required": map[string]string{
					"resource": resource,
					"action":   action,
				},
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyPermission requires user to have any of the specified permissions
func RequireAnyPermission(resource string, actions []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, exists := c.Get("claims")
		if !exists {
			c.JSON(401, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		jwtClaims := claims.(*jwt.Claims)
		if !jwtClaims.HasAnyPermission(resource, actions) {
			c.JSON(403, gin.H{
				"error":   "Forbidden",
				"details": "Missing required permissions",
				"required": map[string]interface{}{
					"resource": resource,
					"actions":  actions,
				},
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireRole creates middleware to check specific role
func RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, exists := c.Get("claims")
		if !exists {
			c.JSON(401, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		jwtClaims := claims.(*jwt.Claims)
		if !jwtClaims.HasRole(role) {
			c.JSON(403, gin.H{
				"error":    "Forbidden",
				"details":  "Missing required role",
				"required": role,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAdmin creates middleware to check admin role
func RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, exists := c.Get("claims")
		if !exists {
			c.JSON(401, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		jwtClaims := claims.(*jwt.Claims)
		if !jwtClaims.IsAdmin() {
			c.JSON(403, gin.H{
				"error":   "Forbidden",
				"details": "Admin access required",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
