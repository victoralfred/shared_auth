package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/victoralfred/shared_auth/jwt"
)

// GetClaims retrieves JWT claims from context
func GetClaims(c *gin.Context) (*jwt.Claims, bool) {
	claims, exists := c.Get("claims")
	if !exists {
		return nil, false
	}

	jwtClaims, ok := claims.(*jwt.Claims)
	return jwtClaims, ok
}

// GetUserID retrieves user ID from context
func GetUserID(c *gin.Context) (string, bool) {
	userID, exists := c.Get("user_id")
	if !exists {
		return "", false
	}

	userIDStr, ok := userID.(string)
	return userIDStr, ok
}

// GetTenantID retrieves tenant ID from context
func GetTenantID(c *gin.Context) (string, bool) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		return "", false
	}

	tenantIDStr, ok := tenantID.(string)
	return tenantIDStr, ok
}

// GetEmail retrieves email from context
func GetEmail(c *gin.Context) (string, bool) {
	email, exists := c.Get("email")
	if !exists {
		return "", false
	}

	emailStr, ok := email.(string)
	return emailStr, ok
}

// GetRoles retrieves roles from context
func GetRoles(c *gin.Context) ([]string, bool) {
	roles, exists := c.Get("roles")
	if !exists {
		return nil, false
	}

	rolesSlice, ok := roles.([]string)
	return rolesSlice, ok
}

// GetPermissions retrieves permissions from context
func GetPermissions(c *gin.Context) (map[string][]string, bool) {
	permissions, exists := c.Get("permissions")
	if !exists {
		return nil, false
	}

	permsMap, ok := permissions.(map[string][]string)
	return permsMap, ok
}
