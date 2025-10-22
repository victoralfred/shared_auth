# Integration Guide: Using shared_auth in kube_manager

This guide shows how to integrate `shared_auth` library into `kube_manager` service using kube_manager's existing infrastructure (Vault, Redis, etc.).

## Overview

```
kube_manager (Your Service)
├── pkg/vault/          ✅ Your own Vault client
├── pkg/redis/          ✅ Your own Redis client
└── internal/adapters/  ✅ NEW: Adapters for shared_auth
    ├── cache.go        ✅ Implements cache.Cache interface
    └── auth.go         ✅ Wires everything together

shared_auth (Pure Library)
├── jwt/interface.go    ✅ Verifier interface
├── policy/interface.go ✅ Engine interface
└── cache/cache.go      ✅ Cache interface
```

---

## Step 1: Create Cache Adapter

Create an adapter that implements `cache.Cache` using kube_manager's Redis client.

**File**: `kube_manager/internal/adapters/cache.go`

```go
package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/victoralfred/shared_auth/cache"
)

// RedisCache implements shared_auth's cache.Cache interface using kube_manager's Redis
type RedisCache struct {
	client *redis.Client
	prefix string
	ctx    context.Context
}

// NewRedisCache creates a cache adapter for shared_auth
func NewRedisCache(client *redis.Client, prefix string) cache.Cache {
	return &RedisCache{
		client: client,
		prefix: prefix,
		ctx:    context.Background(),
	}
}

func (r *RedisCache) Get(key string) (interface{}, bool) {
	fullKey := r.prefix + key

	data, err := r.client.Get(r.ctx, fullKey).Bytes()
	if err == redis.Nil {
		return nil, false
	}
	if err != nil {
		return nil, false
	}

	var value interface{}
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, false
	}

	return value, true
}

func (r *RedisCache) Set(key string, value interface{}, ttl time.Duration) error {
	fullKey := r.prefix + key

	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to serialize value: %w", err)
	}

	return r.client.Set(r.ctx, fullKey, data, ttl).Err()
}

func (r *RedisCache) Delete(key string) error {
	fullKey := r.prefix + key
	return r.client.Del(r.ctx, fullKey).Err()
}

func (r *RedisCache) DeletePattern(pattern string) error {
	fullPattern := r.prefix + pattern

	iter := r.client.Scan(r.ctx, 0, fullPattern, 0).Iterator()
	keys := []string{}
	for iter.Next(r.ctx) {
		keys = append(keys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to scan keys: %w", err)
	}

	if len(keys) > 0 {
		return r.client.Del(r.ctx, keys...).Err()
	}

	return nil
}

func (r *RedisCache) Exists(key string) bool {
	fullKey := r.prefix + key
	count, err := r.client.Exists(r.ctx, fullKey).Result()
	return err == nil && count > 0
}

func (r *RedisCache) Size() int {
	count, err := r.client.DBSize(r.ctx).Result()
	if err != nil {
		return 0
	}
	return int(count)
}

func (r *RedisCache) HitRate() float64 {
	// Implement if you want cache hit tracking
	return 0.0
}

func (r *RedisCache) Clear() error {
	if r.prefix == "" {
		return r.client.FlushDB(r.ctx).Err()
	}
	return r.DeletePattern("*")
}
```

---

## Step 2: Create Auth Service Wrapper

Centralize shared_auth initialization in an auth service.

**File**: `kube_manager/internal/adapters/auth.go`

```go
package adapters

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
	"github.com/victoralfred/kube_manager/pkg/vault"
	"github.com/victoralfred/shared_auth/crypto"
	"github.com/victoralfred/shared_auth/jwt"
	"github.com/victoralfred/shared_auth/policy"
)

// AuthService wraps shared_auth components with kube_manager's infrastructure
type AuthService struct {
	Verifier     jwt.Verifier
	PolicyEngine policy.Engine
	Cache        *RedisCache
}

// NewAuthService initializes shared_auth using kube_manager's infrastructure
func NewAuthService(
	vaultClient *vault.Client,
	redisClient *redis.Client,
) (*AuthService, error) {
	ctx := context.Background()

	// 1. Load JWT public key from kube_manager's Vault
	secretData, err := vaultClient.GetSecret(ctx, "jwt")
	if err != nil {
		return nil, fmt.Errorf("failed to load JWT secret: %w", err)
	}

	publicKeyPEM, ok := secretData["public_key"].(string)
	if !ok {
		return nil, fmt.Errorf("public_key not found in Vault")
	}

	publicKey, err := crypto.ParsePublicKey([]byte(publicKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// 2. Create JWT verifier
	verifier := jwt.NewVerifier(publicKey, "kubemanager", "kubemanager")

	// 3. Create cache adapter using kube_manager's Redis
	authCache := NewRedisCache(redisClient, "auth:")

	// 4. Create policy engine
	policyEngine := policy.NewEngine(authCache)

	// 5. Load initial policies (from database or config)
	// You'd typically load these from your database
	initialPolicies := loadInitialPolicies()
	if err := policyEngine.LoadPolicies(initialPolicies); err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	return &AuthService{
		Verifier:     verifier,
		PolicyEngine: policyEngine,
		Cache:        authCache.(*RedisCache),
	}, nil
}

// loadInitialPolicies loads policies from kube_manager's database
func loadInitialPolicies() []policy.Policy {
	// TODO: Load from database
	// For now, return empty - policies will be loaded dynamically
	return []policy.Policy{}
}
```

---

## Step 3: Initialize in main.go

Wire everything together in kube_manager's main initialization.

**File**: `kube_manager/cmd/server/main.go`

```go
package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/victoralfred/kube_manager/internal/adapters"
	"github.com/victoralfred/kube_manager/pkg/vault"
	"github.com/victoralfred/shared_auth/middleware"
)

func main() {
	// ========================================
	// Initialize kube_manager's infrastructure
	// ========================================

	// 1. Create kube_manager's Vault client
	vaultClient, err := vault.NewClient(vault.Config{
		Address:    os.Getenv("VAULT_ADDR"),
		Token:      os.Getenv("VAULT_TOKEN"),
		MountPath:  "secret",
		SecretPath: "kube_manager",
	})
	if err != nil {
		log.Fatalf("Failed to create Vault client: %v", err)
	}
	defer vaultClient.Close()

	// 2. Create kube_manager's Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})
	defer redisClient.Close()

	// ========================================
	// Initialize shared_auth using adapters
	// ========================================

	authService, err := adapters.NewAuthService(vaultClient, redisClient)
	if err != nil {
		log.Fatalf("Failed to initialize auth service: %v", err)
	}

	log.Println("✓ Auth service initialized")

	// ========================================
	// Setup HTTP routes
	// ========================================

	router := gin.Default()

	// Public routes
	router.POST("/auth/login", loginHandler)
	router.GET("/health", healthHandler)

	// Protected routes
	api := router.Group("/api")
	api.Use(middleware.AuthMiddleware(authService.Verifier))
	{
		// User management
		api.GET("/users",
			middleware.RequirePermission("users", "read"),
			listUsersHandler,
		)

		api.POST("/users",
			middleware.RequirePermission("users", "create"),
			createUserHandler,
		)

		// Role management (admin only)
		api.GET("/roles",
			middleware.RequireAdmin(),
			listRolesHandler,
		)

		api.POST("/roles",
			middleware.RequireAdmin(),
			createRoleHandler,
		)
	}

	log.Println("Starting server on :8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
```

---

## Step 4: Use in Handlers

**File**: `kube_manager/internal/handlers/users.go`

```go
package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/victoralfred/shared_auth/middleware"
)

func ListUsersHandler(c *gin.Context) {
	// Get authenticated user claims
	claims, ok := middleware.GetClaims(c)
	if !ok {
		c.JSON(500, gin.H{"error": "Failed to get claims"})
		return
	}

	// Use claims
	userID := claims.UserID
	tenantID := claims.TenantID

	// Query users for this tenant
	users := queryUsers(tenantID)

	c.JSON(200, gin.H{
		"users":     users,
		"requester": userID,
	})
}

func CreateUserHandler(c *gin.Context) {
	claims, _ := middleware.GetClaims(c)

	// Additional permission check (if needed)
	if !claims.HasPermission("users", "create") {
		c.JSON(403, gin.H{"error": "Forbidden"})
		return
	}

	// Create user logic...
	c.JSON(201, gin.H{"message": "User created"})
}
```

---

## Step 5: Policy Synchronization

When roles/permissions change in kube_manager, update the policy engine.

**File**: `kube_manager/internal/rbac/service.go`

```go
package rbac

import (
	"context"

	"github.com/victoralfred/shared_auth/policy"
)

type RBACService struct {
	repo         *RBACRepository
	policyEngine policy.Engine  // Injected from adapters
}

func (s *RBACService) UpdateRole(ctx context.Context, roleID string, updates RoleUpdate) error {
	// 1. Update database
	err := s.repo.UpdateRole(ctx, roleID, updates)
	if err != nil {
		return err
	}

	// 2. Reload policies into policy engine
	policies, err := s.loadAllPolicies(ctx)
	if err != nil {
		return err
	}

	err = s.policyEngine.LoadPolicies(policies)
	if err != nil {
		return err
	}

	// 3. Invalidate cache for affected users
	// (optional - cache will expire naturally)
	return nil
}

func (s *RBACService) loadAllPolicies(ctx context.Context) ([]policy.Policy, error) {
	// Load from database and convert to policy.Policy format
	roles, err := s.repo.ListRoles(ctx)
	if err != nil {
		return nil, err
	}

	policies := []policy.Policy{}
	for _, role := range roles {
		policies = append(policies, policy.Policy{
			ID:       role.ID,
			TenantID: role.TenantID,
			Resource: role.Resource,
			Actions:  role.Actions,
			Roles:    []string{role.Name},
			Priority: role.Priority,
		})
	}

	return policies, nil
}
```

---

## Step 6: Testing

**File**: `kube_manager/internal/adapters/auth_test.go`

```go
package adapters_test

import (
	"testing"

	"github.com/victoralfred/shared_auth/cache"
	"github.com/victoralfred/shared_auth/jwt"
	"github.com/victoralfred/shared_auth/policy"
)

func TestAuthServiceWithMock(t *testing.T) {
	// Use mock cache for testing (no Redis needed!)
	mockCache := cache.NewMockCache()

	// Create test key
	privateKey, publicKey := generateTestKeys()

	// Create verifier
	verifier := jwt.NewVerifier(publicKey, "kubemanager", "kubemanager")

	// Create policy engine with mock cache
	engine := policy.NewEngine(mockCache)

	// Test...
	token, _ := generateTestToken(privateKey)
	claims, err := verifier.VerifyToken(token)

	if err != nil {
		t.Errorf("Token verification failed: %v", err)
	}

	if claims.UserID == "" {
		t.Error("Expected user ID in claims")
	}
}
```

---

## Benefits of This Integration

### 1. Single Source of Truth

```
kube_manager's infrastructure:
├── Vault client (ONE version, ONE config)
├── Redis client (ONE version, ONE config)
└── Database (ONE connection pool)

shared_auth:
└── Uses kube_manager's infrastructure via adapters
```

No conflicts, no duplication!

### 2. Easy Testing

```go
// Production
authService := adapters.NewAuthService(vaultClient, redisClient)

// Testing
mockCache := cache.NewMockCache()
engine := policy.NewEngine(mockCache)
```

### 3. Future-Proof

When `shared_auth` v3.0 comes out with internal optimizations:
- ✅ Your adapter code stays the same
- ✅ Your integration code stays the same
- ✅ Just update version in go.mod

---

## Common Patterns

### Pattern 1: Lazy-Load Policies

```go
type AuthService struct {
	policyEngine policy.Engine
	repo         *PolicyRepository
	mu           sync.RWMutex
	loaded       bool
}

func (a *AuthService) EnsurePoliciesLoaded(ctx context.Context) error {
	a.mu.RLock()
	if a.loaded {
		a.mu.RUnlock()
		return nil
	}
	a.mu.RUnlock()

	a.mu.Lock()
	defer a.mu.Unlock()

	policies, err := a.repo.LoadAllPolicies(ctx)
	if err != nil {
		return err
	}

	err = a.policyEngine.LoadPolicies(policies)
	if err != nil {
		return err
	}

	a.loaded = true
	return nil
}
```

### Pattern 2: Cache Warmup

```go
func (a *AuthService) WarmupCache(ctx context.Context) error {
	// Pre-load common permission checks
	commonChecks := []policy.PermissionRequest{
		{Resource: "users", Action: "read"},
		{Resource: "roles", Action: "read"},
	}

	for _, req := range commonChecks {
		a.policyEngine.CheckPermission(ctx, req)
	}

	return nil
}
```

### Pattern 3: Health Check

```go
func (a *AuthService) Health(ctx context.Context) error {
	// Check cache
	if !a.Cache.Exists("health") {
		a.Cache.Set("health", "ok", 1*time.Second)
	}

	// Check policy engine
	stats := a.policyEngine.Stats()
	if stats.PolicyCount == 0 {
		return fmt.Errorf("no policies loaded")
	}

	return nil
}
```

---

## Summary

The integration follows this flow:

1. ✅ kube_manager creates **its own** Vault and Redis clients
2. ✅ Adapter implements `cache.Cache` using kube_manager's Redis
3. ✅ Adapter loads JWT keys from kube_manager's Vault
4. ✅ Adapter creates `shared_auth` components and injects dependencies
5. ✅ kube_manager uses `shared_auth` through stable interfaces

**Result**: Zero conflicts, full flexibility, future-proof architecture!
