package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/victoralfred/shared_auth/crypto"
	"github.com/victoralfred/shared_auth/jwt"
	"github.com/victoralfred/shared_auth/middleware"
)

func main() {
	// Load public key for JWT verification
	publicKey, err := crypto.LoadPublicKeyFromFile("../../testdata/jwt-public.pem")
	if err != nil {
		log.Fatalf("Failed to load public key: %v", err)
	}

	// Create JWT verifier
	verifier := jwt.NewVerifier(publicKey, "kubemanager", "basic-auth-example")

	// Setup Gin router
	router := gin.Default()

	// Health check (no auth required)
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy"})
	})

	// Apply authentication middleware to all routes below
	auth := router.Group("/")
	auth.Use(middleware.AuthMiddleware(verifier))
	{
		// Get user profile
		auth.GET("/profile", getProfile)

		// Get user permissions
		auth.GET("/permissions", getPermissions)

		// Protected resource
		auth.GET("/data", getData)
	}

	log.Println("Starting server on :8081")
	if err := router.Run(":8081"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func getProfile(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		c.JSON(500, gin.H{"error": "Failed to get claims"})
		return
	}

	c.JSON(200, gin.H{
		"user_id":   claims.UserID,
		"email":     claims.Email,
		"tenant_id": claims.TenantID,
		"roles":     claims.Roles,
	})
}

func getPermissions(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		c.JSON(500, gin.H{"error": "Failed to get claims"})
		return
	}

	c.JSON(200, gin.H{
		"permissions": claims.Permissions,
		"resources":   claims.GetAllResources(),
	})
}

func getData(c *gin.Context) {
	userID, _ := middleware.GetUserID(c)
	tenantID, _ := middleware.GetTenantID(c)

	c.JSON(200, gin.H{
		"message":   "This is protected data",
		"user_id":   userID,
		"tenant_id": tenantID,
		"data": []string{
			"item1",
			"item2",
			"item3",
		},
	})
}
