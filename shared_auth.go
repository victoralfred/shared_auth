// Package shared_auth provides a production-ready authentication and authorization
// library for Go microservices following interface-based design principles.
//
// # Architecture Philosophy
//
// This library is designed as a pure abstraction - it provides interfaces and
// business logic, but NO infrastructure implementation. Your service provides
// its own Redis, Vault, and other infrastructure components.
//
// # Key Principles
//
//   - Public Interfaces, Private Implementations - Depend only on stable contracts
//   - Zero Infrastructure Dependencies - No Redis, Vault, or database clients
//   - Service-Provided Infrastructure - You implement interfaces using YOUR infrastructure
//   - Future-Proof - Internal changes won't break your services
//
// # Features
//
//   - Stateless JWT Verification - Pure cryptographic signature validation
//   - Policy Engine - Local RBAC/ABAC evaluation without database queries
//   - Embedded Permissions - JWT tokens contain all user permissions
//   - Multi-tenant Support - Tenant-scoped policies and permissions
//   - Interface-Based - Stable public contracts, flexible implementations
//   - Zero Infrastructure - Bring your own Redis, Vault, etc.
//
// # Installation
//
// Install the library using go get:
//
//	go get github.com/victoralfred/shared_auth
//
// # Quick Start Guide
//
// The library follows a simple three-step integration pattern:
//
//	1. Implement the cache.Cache interface using your existing cache infrastructure
//	2. Load JWT public keys from your existing secrets management (Vault, AWS Secrets Manager, etc.)
//	3. Initialize components and use them in your service
//
// # Complete Integration Example
//
// Here's a complete example showing how to integrate shared_auth into your service:
//
//	package main
//
//	import (
//	    "context"
//	    "time"
//
//	    "github.com/gin-gonic/gin"
//	    "github.com/go-redis/redis/v8"
//	    "github.com/victoralfred/shared_auth/cache"
//	    "github.com/victoralfred/shared_auth/crypto"
//	    "github.com/victoralfred/shared_auth/jwt"
//	    "github.com/victoralfred/shared_auth/middleware"
//	    "github.com/victoralfred/shared_auth/policy"
//	)
//
//	// Step 1: Implement cache.Cache interface using your Redis client
//	type RedisCache struct {
//	    client *redis.Client
//	    prefix string
//	}
//
//	func (r *RedisCache) Get(key string) (interface{}, bool) {
//	    val, err := r.client.Get(context.Background(), r.prefix+key).Result()
//	    if err != nil {
//	        return nil, false
//	    }
//	    return val, true
//	}
//
//	func (r *RedisCache) Set(key string, value interface{}, ttl time.Duration) error {
//	    return r.client.Set(context.Background(), r.prefix+key, value, ttl).Err()
//	}
//
//	func (r *RedisCache) Delete(key string) error {
//	    return r.client.Del(context.Background(), r.prefix+key).Err()
//	}
//
//	func (r *RedisCache) DeletePattern(pattern string) error {
//	    iter := r.client.Scan(context.Background(), 0, r.prefix+pattern, 0).Iterator()
//	    keys := []string{}
//	    for iter.Next(context.Background()) {
//	        keys = append(keys, iter.Val())
//	    }
//	    if len(keys) > 0 {
//	        return r.client.Del(context.Background(), keys...).Err()
//	    }
//	    return nil
//	}
//
//	func (r *RedisCache) Exists(key string) bool {
//	    count, _ := r.client.Exists(context.Background(), r.prefix+key).Result()
//	    return count > 0
//	}
//
//	func (r *RedisCache) Size() int {
//	    count, _ := r.client.DBSize(context.Background()).Result()
//	    return int(count)
//	}
//
//	func (r *RedisCache) HitRate() float64 {
//	    return 0.0 // Implement if needed
//	}
//
//	func (r *RedisCache) Clear() error {
//	    return r.client.FlushDB(context.Background()).Err()
//	}
//
//	func main() {
//	    // Step 2: Initialize your infrastructure
//	    redisClient := redis.NewClient(&redis.Options{
//	        Addr: "localhost:6379",
//	    })
//
//	    // Create cache adapter
//	    authCache := &RedisCache{
//	        client: redisClient,
//	        prefix: "auth:",
//	    }
//
//	    // Load JWT public key from your secrets management
//	    // Option 1: From file
//	    publicKey, _ := crypto.LoadPublicKeyFromFile("/path/to/jwt_public.pem")
//
//	    // Option 2: From environment variable
//	    // publicKey, _ := crypto.LoadPublicKeyFromEnv("JWT_PUBLIC_KEY")
//
//	    // Option 3: From your Vault client
//	    // vaultClient, _ := vault.NewClient(...)
//	    // publicKeyPEM, _ := vaultClient.GetSecret(ctx, "jwt/public_key")
//	    // publicKey, _ := crypto.ParsePublicKey([]byte(publicKeyPEM))
//
//	    // Step 3: Create shared_auth components
//	    verifier := jwt.NewVerifier(publicKey, "your-issuer", "your-audience")
//	    policyEngine := policy.NewEngine(authCache)
//
//	    // Load policies into the engine
//	    policies := []policy.Policy{
//	        {
//	            ID:       "customer-read-orders",
//	            TenantID: "*",
//	            Resource: "orders",
//	            Actions:  []string{"read"},
//	            Roles:    []string{"customer"},
//	        },
//	        {
//	            ID:       "admin-full-access",
//	            TenantID: "*",
//	            Resource: "*",
//	            Actions:  []string{"*"},
//	            Roles:    []string{"admin"},
//	        },
//	    }
//	    policyEngine.LoadPolicies(policies)
//
//	    // Use in your HTTP server
//	    router := gin.Default()
//
//	    // Apply authentication middleware globally
//	    router.Use(middleware.AuthMiddleware(verifier))
//
//	    // Protect endpoints with permission checks
//	    router.GET("/orders", middleware.RequirePermission("orders", "read"), listOrders)
//	    router.POST("/orders", middleware.RequirePermission("orders", "create"), createOrder)
//	    router.GET("/admin", middleware.RequireAdmin(), adminDashboard)
//
//	    router.Run(":8080")
//	}
//
//	func listOrders(c *gin.Context) {
//	    // Get claims from context
//	    claims, _ := c.Get("claims")
//	    jwtClaims := claims.(*jwt.Claims)
//
//	    c.JSON(200, gin.H{
//	        "user_id": jwtClaims.UserID,
//	        "orders":  []string{"order1", "order2"},
//	    })
//	}
//
//	func createOrder(c *gin.Context) {
//	    c.JSON(201, gin.H{"message": "Order created"})
//	}
//
//	func adminDashboard(c *gin.Context) {
//	    c.JSON(200, gin.H{"message": "Admin dashboard"})
//	}
//
// # Available Packages
//
// The library is organized into focused packages:
//
//	jwt         - JWT token verification and claims handling
//	policy      - Policy engine for RBAC/ABAC permission evaluation
//	middleware  - Gin middleware for authentication and authorization
//	cache       - Cache interface (you implement this)
//	crypto      - Cryptographic key loading utilities
//	events      - Event models for policy updates and cache invalidation
//
// # JWT Verification
//
// The jwt package provides stateless token verification:
//
//	import "github.com/victoralfred/shared_auth/jwt"
//
//	// Create verifier
//	verifier := jwt.NewVerifier(publicKey, "kubemanager", "my-service")
//
//	// Verify token
//	claims, err := verifier.VerifyToken(tokenString)
//	if err != nil {
//	    // Invalid token
//	}
//
//	// Check permissions embedded in token
//	if claims.HasPermission("orders", "create") {
//	    // User can create orders
//	}
//
//	// Check roles
//	if claims.HasRole("admin") {
//	    // User is admin
//	}
//
// # Policy Engine
//
// The policy package evaluates permissions locally without database queries:
//
//	import "github.com/victoralfred/shared_auth/policy"
//
//	// Create engine with your cache implementation
//	engine := policy.NewEngine(yourCacheImplementation)
//
//	// Load policies
//	policies := []policy.Policy{
//	    {
//	        ID:       "manager-create-orders",
//	        TenantID: "tenant-123",
//	        Resource: "orders",
//	        Actions:  []string{"create", "read", "update"},
//	        Roles:    []string{"manager"},
//	    },
//	}
//	engine.LoadPolicies(policies)
//
//	// Check permission
//	decision, err := engine.CheckPermission(ctx, policy.PermissionRequest{
//	    UserID:   "user-456",
//	    TenantID: "tenant-123",
//	    Roles:    []string{"manager"},
//	    Resource: "orders",
//	    Action:   "create",
//	})
//
//	if decision.Allowed {
//	    // Permission granted
//	}
//
// # Middleware
//
// The middleware package provides ready-to-use Gin middleware:
//
//	import "github.com/victoralfred/shared_auth/middleware"
//
//	router := gin.Default()
//
//	// Authentication - validates JWT tokens
//	router.Use(middleware.AuthMiddleware(verifier))
//
//	// Permission-based authorization
//	router.POST("/orders",
//	    middleware.RequirePermission("orders", "create"),
//	    createOrderHandler,
//	)
//
//	// Role-based authorization
//	router.GET("/admin",
//	    middleware.RequireRole("admin"),
//	    adminHandler,
//	)
//
//	// Multiple permissions (requires ANY)
//	router.GET("/reports",
//	    middleware.RequireAnyPermission("reports", []string{"read", "download"}),
//	    reportsHandler,
//	)
//
//	// Optional authentication (doesn't fail if no token)
//	router.GET("/public",
//	    middleware.OptionalAuthMiddleware(verifier),
//	    publicHandler,
//	)
//
// # Cache Interface
//
// You must implement the cache.Cache interface using your infrastructure:
//
//	import "github.com/victoralfred/shared_auth/cache"
//
//	// For testing, use the mock cache
//	mockCache := cache.NewMockCache()
//	engine := policy.NewEngine(mockCache)
//
//	// For production, implement the interface with your Redis/Memcached
//	type YourCache struct {
//	    // Your cache client
//	}
//
//	func (c *YourCache) Get(key string) (interface{}, bool) { ... }
//	func (c *YourCache) Set(key string, value interface{}, ttl time.Duration) error { ... }
//	// ... implement other methods
//
// # Crypto Utilities
//
// The crypto package provides helper functions for loading RSA keys:
//
//	import "github.com/victoralfred/shared_auth/crypto"
//
//	// Load from file
//	publicKey, err := crypto.LoadPublicKeyFromFile("/path/to/key.pem")
//
//	// Load from environment variable
//	publicKey, err := crypto.LoadPublicKeyFromEnv("JWT_PUBLIC_KEY")
//
//	// Parse from PEM bytes
//	publicKey, err := crypto.ParsePublicKey(pemBytes)
//
//	// Same for private keys
//	privateKey, err := crypto.LoadPrivateKeyFromFile("/path/to/key.pem")
//
// # Testing
//
// The library provides mock implementations for testing:
//
//	import (
//	    "testing"
//	    "github.com/victoralfred/shared_auth/cache"
//	    "github.com/victoralfred/shared_auth/policy"
//	)
//
//	func TestMyService(t *testing.T) {
//	    // Use mock cache - no Redis needed
//	    mockCache := cache.NewMockCache()
//	    engine := policy.NewEngine(mockCache)
//
//	    // Test your service logic
//	}
//
// # Multi-Tenant Support
//
// The library supports multi-tenant applications:
//
//	// Policies are tenant-scoped
//	policy := policy.Policy{
//	    ID:       "tenant-specific-policy",
//	    TenantID: "tenant-123",  // Specific tenant
//	    Resource: "documents",
//	    Actions:  []string{"read"},
//	    Roles:    []string{"user"},
//	}
//
//	// Use "*" for global policies
//	globalPolicy := policy.Policy{
//	    ID:       "global-admin-policy",
//	    TenantID: "*",  // All tenants
//	    Resource: "*",
//	    Actions:  []string{"*"},
//	    Roles:    []string{"super_admin"},
//	}
//
//	// JWT claims contain tenant ID
//	claims.TenantID  // "tenant-123"
//
// # Error Handling
//
// The library provides clear error types:
//
//	claims, err := verifier.VerifyToken(tokenString)
//	if err != nil {
//	    switch {
//	    case errors.Is(err, jwt.ErrInvalidToken):
//	        // Token is malformed
//	    case errors.Is(err, jwt.ErrExpiredToken):
//	        // Token has expired
//	    case errors.Is(err, jwt.ErrInvalidSignature):
//	        // Signature verification failed
//	    case errors.Is(err, jwt.ErrInvalidIssuer):
//	        // Issuer doesn't match
//	    case errors.Is(err, jwt.ErrInvalidAudience):
//	        // Audience doesn't match
//	    }
//	}
//
// # Version Compatibility
//
// Current version: v2.0.0 (Interface-based design)
//
// Breaking changes from v1.x:
//   - Removed built-in Vault client
//   - Removed built-in Redis implementation
//   - All implementations now private (use interfaces)
//   - Services must implement cache.Cache interface
//
// # Additional Resources
//
// For more detailed information:
//   - Architecture: See docs/ARCHITECTURE.md
//   - Integration Guide: See docs/INTEGRATION_GUIDE.md
//   - Full Examples: See README.md
//   - API Documentation: https://pkg.go.dev/github.com/victoralfred/shared_auth
package shared_auth

// Version is the current version of the shared_auth library
const Version = "v1.0.2"