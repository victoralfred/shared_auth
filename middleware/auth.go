// Package middleware provides ready-to-use HTTP middleware for authentication and authorization.
//
// This package integrates with the Gin web framework to provide easy-to-use middleware
// functions for JWT authentication and permission/role-based authorization.
//
// # Features
//
//   - JWT authentication middleware
//   - Permission-based authorization middleware
//   - Role-based authorization middleware
//   - Optional authentication (for public endpoints with conditional logic)
//   - Automatic claims storage in Gin context
//   - Standard HTTP status codes (401 Unauthorized, 403 Forbidden)
//
// # Quick Start
//
// Apply authentication middleware to your Gin router:
//
//	import (
//	    "github.com/gin-gonic/gin"
//	    "github.com/victoralfred/shared_auth/middleware"
//	    "github.com/victoralfred/shared_auth/jwt"
//	)
//
//	verifier := jwt.NewVerifier(publicKey, "your-issuer", "your-audience")
//	router := gin.Default()
//
//	// Apply authentication globally
//	router.Use(middleware.AuthMiddleware(verifier))
//
//	// All routes now require valid JWT token
//	router.GET("/profile", profileHandler)
//	router.POST("/orders", createOrderHandler)
//
// # Permission-Based Authorization
//
// Require specific permissions for endpoints:
//
//	router.POST("/orders",
//	    middleware.RequirePermission("orders", "create"),
//	    createOrderHandler,
//	)
//
//	router.DELETE("/orders/:id",
//	    middleware.RequirePermission("orders", "delete"),
//	    deleteOrderHandler,
//	)
//
//	// Require any of multiple actions
//	router.GET("/reports",
//	    middleware.RequireAnyPermission("reports", []string{"read", "download"}),
//	    reportsHandler,
//	)
//
// # Role-Based Authorization
//
// Require specific roles for endpoints:
//
//	// Single role required
//	router.GET("/admin",
//	    middleware.RequireRole("admin"),
//	    adminHandler,
//	)
//
//	// Admin role (checks for "admin" or "super_admin")
//	router.DELETE("/users/:id",
//	    middleware.RequireAdmin(),
//	    deleteUserHandler,
//	)
//
// # Optional Authentication
//
// For public endpoints that want to know if user is authenticated:
//
//	router.GET("/products",
//	    middleware.OptionalAuthMiddleware(verifier),
//	    func(c *gin.Context) {
//	        claims, exists := c.Get("claims")
//	        if exists {
//	            // User is authenticated - show personalized content
//	            userID := claims.(*jwt.Claims).UserID
//	            products := getPersonalizedProducts(userID)
//	            c.JSON(200, products)
//	        } else {
//	            // User is not authenticated - show public content
//	            products := getPublicProducts()
//	            c.JSON(200, products)
//	        }
//	    },
//	)
//
// # Accessing Claims in Handlers
//
// Get user information from the Gin context:
//
//	func orderHandler(c *gin.Context) {
//	    // Get claims
//	    claims, _ := c.Get("claims")
//	    jwtClaims := claims.(*jwt.Claims)
//
//	    // Access user information
//	    userID := jwtClaims.UserID
//	    tenantID := jwtClaims.TenantID
//	    email := jwtClaims.Email
//	    roles := jwtClaims.Roles
//
//	    // Or use individual context values
//	    userID, _ := c.Get("user_id")
//	    tenantID, _ := c.Get("tenant_id")
//	    email, _ := c.Get("email")
//	    roles, _ := c.Get("roles")
//	    permissions, _ := c.Get("permissions")
//	}
//
// # Middleware Chain Example
//
// Combine multiple middleware for complex authorization:
//
//	// Authentication required for all /api routes
//	api := router.Group("/api")
//	api.Use(middleware.AuthMiddleware(verifier))
//	{
//	    // Public endpoint (authenticated users only)
//	    api.GET("/profile", profileHandler)
//
//	    // Admin-only endpoints
//	    admin := api.Group("/admin")
//	    admin.Use(middleware.RequireAdmin())
//	    {
//	        admin.GET("/users", listUsersHandler)
//	        admin.DELETE("/users/:id", deleteUserHandler)
//	    }
//
//	    // Resource-specific permissions
//	    api.GET("/orders", middleware.RequirePermission("orders", "read"), listOrdersHandler)
//	    api.POST("/orders", middleware.RequirePermission("orders", "create"), createOrderHandler)
//	}
//
// # Error Responses
//
// The middleware returns standard error responses:
//
//	// 401 Unauthorized - No token, invalid token, or expired token
//	{
//	    "error": "Authorization header required"
//	}
//	{
//	    "error": "Invalid token",
//	    "details": "token expired"
//	}
//
//	// 403 Forbidden - Missing permission or role
//	{
//	    "error": "Forbidden",
//	    "details": "Missing required permission",
//	    "required": {
//	        "resource": "orders",
//	        "action": "create"
//	    }
//	}
//
// # Token Format
//
// Tokens must be provided in the Authorization header:
//
//	Authorization: Bearer <token>
//
// Example HTTP request:
//
//	GET /api/orders HTTP/1.1
//	Host: example.com
//	Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
//
// # Complete Example
//
// Full application setup with authentication and authorization:
//
//	package main
//
//	import (
//	    "github.com/gin-gonic/gin"
//	    "github.com/victoralfred/shared_auth/crypto"
//	    "github.com/victoralfred/shared_auth/jwt"
//	    "github.com/victoralfred/shared_auth/middleware"
//	)
//
//	func main() {
//	    // Load JWT public key
//	    publicKey, _ := crypto.LoadPublicKeyFromFile("/path/to/jwt_public.pem")
//
//	    // Create verifier
//	    verifier := jwt.NewVerifier(publicKey, "your-issuer", "your-audience")
//
//	    // Setup router
//	    router := gin.Default()
//
//	    // Public routes (no authentication)
//	    router.GET("/health", healthHandler)
//	    router.POST("/login", loginHandler)
//
//	    // Authenticated routes
//	    api := router.Group("/api")
//	    api.Use(middleware.AuthMiddleware(verifier))
//	    {
//	        // All users can access
//	        api.GET("/profile", profileHandler)
//
//	        // Permission-based access
//	        api.GET("/orders",
//	            middleware.RequirePermission("orders", "read"),
//	            listOrdersHandler,
//	        )
//	        api.POST("/orders",
//	            middleware.RequirePermission("orders", "create"),
//	            createOrderHandler,
//	        )
//
//	        // Admin-only access
//	        api.GET("/admin",
//	            middleware.RequireAdmin(),
//	            adminDashboardHandler,
//	        )
//	    }
//
//	    router.Run(":8080")
//	}
//
// # Context Values
//
// The AuthMiddleware stores these values in the Gin context:
//
//	c.Get("user_id")      // string - User ID
//	c.Get("tenant_id")    // string - Tenant ID
//	c.Get("email")        // string - User email
//	c.Get("roles")        // []string - User roles
//	c.Get("permissions")  // map[string][]string - User permissions
//	c.Get("claims")       // *jwt.Claims - Full claims object
//
// # Performance
//
//   - Token verification is fast (< 1ms typically)
//   - No database queries during authentication
//   - Suitable for high-throughput applications
//   - Minimal overhead per request
//
// # Best Practices
//
//   - Apply AuthMiddleware globally or to route groups
//   - Use RequirePermission for resource-specific access control
//   - Use RequireRole for role-based access control
//   - Use RequireAdmin for administrative endpoints
//   - Handle authorization at the middleware level, not in handlers
//   - Keep permission granularity reasonable
//   - Use OptionalAuthMiddleware for hybrid public/private endpoints
package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/victoralfred/shared_auth/jwt"
)

// AuthMiddleware creates Gin middleware for JWT authentication
func AuthMiddleware(verifier jwt.Verifier) gin.HandlerFunc {
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
func OptionalAuthMiddleware(verifier jwt.Verifier) gin.HandlerFunc {
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
