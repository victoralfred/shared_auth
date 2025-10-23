# Shared Authentication Library

A production-ready authentication and authorization library for Go microservices following **interface-based design principles**.

## Architecture Philosophy

This library is designed as a **pure abstraction** - it provides interfaces and business logic, but **NO infrastructure implementation**. Your service provides its own Redis, Vault, and other infrastructure components.

### Key Principles

1. **Public Interfaces, Private Implementations** - Depend only on stable contracts
2. **Zero Infrastructure Dependencies** - No Redis, Vault, or database clients
3. **Service-Provided Infrastructure** - You implement interfaces using YOUR infrastructure
4. **Future-Proof** - Internal changes won't break your services

## Features

- ✅ **Stateless JWT Verification** - Pure cryptographic signature validation
- ✅ **Policy Engine** - Local RBAC/ABAC evaluation without database queries
- ✅ **Embedded Permissions** - JWT tokens contain all user permissions
- ✅ **Multi-tenant Support** - Tenant-scoped policies and permissions
- ✅ **Interface-Based** - Stable public contracts, flexible implementations
- ✅ **Zero Infrastructure** - Bring your own Redis, Vault, etc.

## Installation

```bash
go get github.com/victoralfred/shared_auth
```

## Quick Start

### Step 1: Implement the Cache Interface

Using your service's own Redis client:

```go
// In your service: internal/adapters/cache.go
package adapters

import (
    "context"
    "encoding/json"
    "time"

    "github.com/go-redis/redis/v8"
    "github.com/victoralfred/shared_auth/cache"
)

type RedisCache struct {
    client *redis.Client
    prefix string
}

func NewRedisCache(client *redis.Client, prefix string) cache.Cache {
    return &RedisCache{client: client, prefix: prefix}
}

func (r *RedisCache) Get(key string) (interface{}, bool) {
    val, err := r.client.Get(context.Background(), r.prefix+key).Result()
    if err != nil {
        return nil, false
    }
    var result interface{}
    json.Unmarshal([]byte(val), &result)
    return result, true
}

func (r *RedisCache) Set(key string, value interface{}, ttl time.Duration) error {
    data, _ := json.Marshal(value)
    return r.client.Set(context.Background(), r.prefix+key, data, ttl).Err()
}

func (r *RedisCache) Delete(key string) error {
    return r.client.Del(context.Background(), r.prefix+key).Err()
}

func (r *RedisCache) DeletePattern(pattern string) error {
    iter := r.client.Scan(context.Background(), 0, r.prefix+pattern, 0).Iterator()
    keys := []string{}
    for iter.Next(context.Background()) {
        keys = append(keys, iter.Val())
    }
    if len(keys) > 0 {
        return r.client.Del(context.Background(), keys...).Err()
    }
    return nil
}

func (r *RedisCache) Exists(key string) bool {
    count, _ := r.client.Exists(context.Background(), r.prefix+key).Result()
    return count > 0
}

func (r *RedisCache) Size() int {
    count, _ := r.client.DBSize(context.Background()).Result()
    return int(count)
}

func (r *RedisCache) HitRate() float64 {
    return 0.0 // Implement if needed
}

func (r *RedisCache) Clear() error {
    return r.client.FlushDB(context.Background()).Err()
}
```

### Step 2: Load JWT Keys From Your Vault

Using your service's own Vault client:

```go
// Using your existing Vault infrastructure
import "github.com/victoralfred/kube_manager/pkg/vault"

vaultClient, _ := vault.NewClient(vault.Config{
    Address:    os.Getenv("VAULT_ADDR"),
    Token:      os.Getenv("VAULT_TOKEN"),
    MountPath:  "secret",
    SecretPath: "kube_manager",
})

// Load JWT public key from YOUR Vault
secretData, _ := vaultClient.GetSecret(context.Background(), "jwt")
publicKeyPEM := secretData["public_key"].(string)

// Parse the key
publicKey, _ := crypto.ParsePublicKey([]byte(publicKeyPEM))
```

### Step 3: Initialize Shared Auth Components

```go
package main

import (
    "github.com/go-redis/redis/v8"
    "github.com/victoralfred/shared_auth/jwt"
    "github.com/victoralfred/shared_auth/policy"
    "github.com/victoralfred/shared_auth/middleware"

    "your-service/internal/adapters"  // Your cache adapter
)

func main() {
    // 1. Create YOUR infrastructure
    redisClient := redis.NewClient(&redis.Options{
        Addr: "localhost:6379",
    })

    // 2. Create adapters
    authCache := adapters.NewRedisCache(redisClient, "auth:")

    // 3. Create JWT verifier (returns interface)
    verifier := jwt.NewVerifier(publicKey, "kubemanager", "my-service")

    // 4. Create policy engine (inject YOUR cache)
    engine := policy.NewEngine(authCache)

    // 5. Load policies
    policies := []policy.Policy{
        {
            ID:       "customer-read",
            TenantID: "*",
            Resource: "orders",
            Actions:  []string{"read"},
            Roles:    []string{"customer"},
        },
    }
    engine.LoadPolicies(policies)

    // 6. Use in Gin middleware
    router := gin.Default()
    router.Use(middleware.AuthMiddleware(verifier))

    router.GET("/orders",
        middleware.RequirePermission("orders", "read"),
        listOrders,
    )

    router.Run(":8080")
}
```

## Public Interfaces

### jwt.Verifier

```go
type Verifier interface {
    VerifyToken(tokenString string) (*Claims, error)
    VerifyAccessToken(tokenString string) (*Claims, error)
    VerifyRefreshToken(tokenString string) (*Claims, error)
}

// Factory function
func NewVerifier(publicKey *rsa.PublicKey, issuer, audience string) Verifier
```

### policy.Engine

```go
type Engine interface {
    LoadPolicies(policies []Policy) error
    CheckPermission(ctx context.Context, req PermissionRequest) (*Decision, error)
    InvalidateCache(userID, tenantID string) error
    Stats() EngineStats
}

// Factory function
func NewEngine(cacheBackend cache.Cache) Engine
```

### cache.Cache

```go
type Cache interface {
    Get(key string) (interface{}, bool)
    Set(key string, value interface{}, ttl time.Duration) error
    Delete(key string) error
    DeletePattern(pattern string) error
    Exists(key string) bool
    Size() int
    HitRate() float64
    Clear() error
}
```

**You implement this interface using YOUR Redis, Memcached, or any other cache.**

## Why Interface-Based Design?

### ❌ Problem With Traditional Approach

```go
// BAD: Library owns infrastructure
shared_auth/
├── vault/client.go      // ❌ Conflicts with your Vault
├── cache/redis.go       // ❌ Conflicts with your Redis
```

**Issues:**
- Dependency version conflicts
- Can't customize infrastructure
- Hard to test (can't inject mocks)
- Library updates break your service

### ✅ Solution: Interface-Based Design

```go
// GOOD: Library provides interfaces only
shared_auth/
├── cache/cache.go       // ✅ Interface only
├── jwt/interface.go     // ✅ Public contract
├── policy/interface.go  // ✅ Public contract

// You implement using YOUR infrastructure
your-service/
├── pkg/vault/           // ✅ Your Vault client
├── internal/adapters/   // ✅ Implements shared_auth interfaces
    └── cache.go         // ✅ Uses YOUR Redis
```

**Benefits:**
- ✅ No conflicts - single source of truth
- ✅ Fully customizable - use any infrastructure
- ✅ Testable - inject mocks easily
- ✅ Future-proof - internal changes don't break you

## Testing

### Unit Tests

Use the provided mock cache for testing:

```go
import "github.com/victoralfred/shared_auth/cache"

func TestMyService(t *testing.T) {
    // Use mock cache (no Redis needed)
    mockCache := cache.NewMockCache()

    // Create engine
    engine := policy.NewEngine(mockCache)

    // Run tests...
}
```

### Integration Tests

Use your real infrastructure:

```go
func TestIntegration(t *testing.T) {
    // Use real Redis
    redisClient := redis.NewClient(&redis.Options{
        Addr: "localhost:6379",
    })

    authCache := adapters.NewRedisCache(redisClient, "test:")
    engine := policy.NewEngine(authCache)

    // Run integration tests...
}
```

## Documentation

- [Architecture Guide](docs/ARCHITECTURE.md) - Interface-based design principles
- [API Reference](https://pkg.go.dev/github.com/victoralfred/shared_auth) - Full godoc

## Key Components

### JWT Verification

```go
// Stateless verification - no database queries
verifier := jwt.NewVerifier(publicKey, "kubemanager", "my-service")

claims, err := verifier.VerifyToken(tokenString)
if err != nil {
    // Invalid token
}

// Check embedded permissions
if claims.HasPermission("orders", "create") {
    // User can create orders
}
```

### Policy Engine

```go
// Local RBAC/ABAC evaluation - no database queries
decision, err := engine.CheckPermission(ctx, policy.PermissionRequest{
    UserID:   "user-123",
    TenantID: "tenant-456",
    Roles:    []string{"manager"},
    Resource: "orders",
    Action:   "create",
    Context: map[string]interface{}{
        "department": "finance",
    },
})

if decision.Allowed {
    // Permission granted
}
```

### Middleware

```go
// Authentication middleware
router.Use(middleware.AuthMiddleware(verifier))

// Permission-based authorization
router.POST("/orders",
    middleware.RequirePermission("orders", "create"),
    createOrder,
)

// Role-based authorization
router.GET("/admin",
    middleware.RequireAdmin(),
    adminDashboard,
)
```

## Migration From Old Design

If you were using an older version with built-in Vault/Redis:

1. **Create cache adapter** (see Step 1 above)
2. **Load keys from YOUR Vault** (see Step 2 above)
3. **Inject dependencies** (see Step 3 above)

The public interfaces remain the same - only how you create them changes.

## Contributing

1. Fork the repository
2. Create feature branch
3. Make changes (keep interfaces stable!)
4. Add tests
5. Submit pull request

## License

MIT License - see [LICENSE](LICENSE)

## Version

Current: v1.0.1 (Interface-based design)

## Breaking Changes from v1.x

- Removed built-in Vault client
- Removed built-in Redis implementation
- All implementations now private (use interfaces)
- Services must implement `cache.Cache` interface

See [CHANGELOG.md](CHANGELOG.md) for details.
