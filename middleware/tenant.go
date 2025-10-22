package middleware

import (
	"github.com/gin-gonic/gin"
)

// TenantMiddleware enforces tenant isolation
func TenantMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, exists := c.Get("tenant_id")
		if !exists {
			c.JSON(401, gin.H{"error": "Tenant ID not found in token"})
			c.Abort()
			return
		}

		// Store tenant ID for easy access
		c.Set("current_tenant_id", tenantID)

		c.Next()
	}
}

// RequireTenant validates that tenant_id matches
func RequireTenant(expectedTenantID string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, exists := c.Get("tenant_id")
		if !exists {
			c.JSON(401, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		if tenantID != expectedTenantID {
			c.JSON(403, gin.H{"error": "Forbidden - tenant mismatch"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// ExtractTenantID helper to get tenant ID from context
func ExtractTenantID(c *gin.Context) (string, bool) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		return "", false
	}

	tenantIDStr, ok := tenantID.(string)
	return tenantIDStr, ok
}

// ExtractUserID helper to get user ID from context
func ExtractUserID(c *gin.Context) (string, bool) {
	userID, exists := c.Get("user_id")
	if !exists {
		return "", false
	}

	userIDStr, ok := userID.(string)
	return userIDStr, ok
}
