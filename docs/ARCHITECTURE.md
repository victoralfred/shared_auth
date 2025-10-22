# Architecture: Interface-Based Design

## Overview

The `shared_auth` library follows the **Dependency Inversion Principle** to provide a stable, production-ready authentication and authorization solution.

### Key Design Principles

1. **Public Interfaces, Private Implementations** - Consuming services depend only on interfaces
2. **Zero Infrastructure Dependencies** - No Redis, Vault, or database implementations
3. **Service-Provided Infrastructure** - Consuming services implement interfaces using THEIR infrastructure
4. **Future-Proof** - Internal changes don't break existing services

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Consuming Service                               │
│                     (kube_manager, etc.)                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐      │
│  │ Vault Client │      │ Redis Client │      │   Database   │      │
│  │ (pkg/vault)  │      │  (own impl)  │      │   (own impl) │      │
│  └──────┬───────┘      └──────┬───────┘      └──────┬───────┘      │
│         │                     │                      │              │
│         │  Implements         │  Implements          │              │
│         │  Adapter            │  Adapter             │              │
│         ▼                     ▼                      ▼              │
│  ┌─────────────────────────────────────────────────────────┐       │
│  │           Service-Specific Adapters                      │       │
│  │  • VaultKeyProvider (implements crypto loading)         │       │
│  │  • RedisCache (implements cache.Cache)                  │       │
│  │  • ... other adapters                                   │       │
│  └───────────────────────┬──────────────────────────────────┘       │
│                          │ Injects                                  │
│                          ▼                                          │
│  ┌──────────────────────────────────────────────────┐              │
│  │           shared_auth Library                     │              │
│  │  ┌────────────────┐  ┌────────────────┐          │              │
│  │  │  jwt.Verifier  │  │ policy.Engine  │          │              │
│  │  │  (interface)   │  │  (interface)   │          │              │
│  │  └────────┬───────┘  └────────┬───────┘          │              │
│  │           │ Uses              │ Uses              │              │
│  │           ▼                   ▼                   │              │
│  │  ┌────────────────┐  ┌────────────────┐          │              │
│  │  │   verifier     │  │    engine      │          │              │
│  │  │  (private impl)│  │  (private impl)│          │              │
│  │  └────────────────┘  └────────────────┘          │              │
│  └──────────────────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────────────┘
```

---

Interface-Based

```go
// ✅ shared_auth ONLY has interfaces
shared_auth/
├── cache/
│   ├── cache.go    // ✅ Interface ONLY
│   └── mock.go     // ✅ Mock for testing only
├── jwt/
│   ├── interface.go    // ✅ Public interface
│   └── verifier.go     // ✅ Private implementation
├── policy/
│   ├── interface.go    // ✅ Public interface
│   └── engine.go       // ✅ Private implementation
└── crypto/
    └── keys.go     // ✅ No Vault dependency

// ✅ kube_manager implements interfaces
kube_manager/
├── pkg/vault/          // kube_manager's Vault
├── internal/adapters/  // NEW: Adapters for shared_auth
│   ├── cache.go        // Implements cache.Cache
│   └── keygen.go       // Loads keys from kube_manager's Vault
└── ...
```

**Benefits:**
1. **No conflicts** - Single source of truth for infrastructure
2. **Flexibility** - Swap Redis for Memcached easily
3. **Testable** - Inject mocks during testing
4. **Future-proof** - Interface stays stable, impl can change
5. **Clean separation** - Library is pure business logic

---

## Public Interfaces

### 1. jwt.Verifier Interface

```go
// Public interface (STABLE CONTRACT)
type Verifier interface {
    VerifyToken(tokenString string) (*Claims, error)
    VerifyAccessToken(tokenString string) (*Claims, error)
    VerifyRefreshToken(tokenString string) (*Claims, error)
}

// Private implementation (CAN CHANGE)
type verifier struct {
    publicKey *rsa.PublicKey
    issuer    string
    audience  string
}

// Factory returns interface
func NewVerifier(publicKey *rsa.PublicKey, issuer, audience string) Verifier {
    return &verifier{...}  // Returns interface, hides implementation
}
```

**Usage in kube_manager:**
```go
// Load key using kube_manager's OWN Vault
vaultClient, _ := vault.NewClient(vaultConfig)  // kube_manager's vault!
publicKey, _ := vaultClient.GetSecret(ctx, "jwt/public_key")

// Create verifier (returns interface)
verifier := jwt.NewVerifier(publicKey, "kubemanager", "my-service")

// Use through interface
claims, err := verifier.VerifyToken(tokenString)
```

---

### 2. policy.Engine Interface

```go
// Public interface (STABLE CONTRACT)
type Engine interface {
    LoadPolicies(policies []Policy) error
    CheckPermission(ctx context.Context, req PermissionRequest) (*Decision, error)
    InvalidateCache(userID, tenantID string) error
    Stats() EngineStats
}

// Private implementation (CAN CHANGE)
type engine struct {
    cache     cache.Cache  // Injected by service
    evaluator *Evaluator
    policies  *PolicyStore
}

// Factory returns interface
func NewEngine(cacheBackend cache.Cache) Engine {
    return &engine{cache: cacheBackend, ...}
}
```

**Usage in kube_manager:**
```go
// Create adapter using kube_manager's Redis
type RedisCache struct {
    client *kube_manager_redis.Client  // kube_manager's Redis!
}

func (r *RedisCache) Get(key string) (interface{}, bool) {
    // Implements cache.Cache interface using kube_manager's Redis
}

// Create policy engine (inject adapter)
redisCache := &RedisCache{client: redisClient}
engine := policy.NewEngine(redisCache)
```

---

### 3. cache.Cache Interface

```go
// Public interface (services implement this)
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

**kube_manager implements this:**
```go
// In kube_manager/internal/adapters/cache.go
type RedisCache struct {
    client *redis.Client  // kube_manager's own Redis client
    prefix string
}

func (r *RedisCache) Get(key string) (interface{}, bool) {
    val, err := r.client.Get(ctx, r.prefix+key).Result()
    if err != nil {
        return nil, false
    }
    return val, true
}

func (r *RedisCache) Set(key string, value interface{}, ttl time.Duration) error {
    return r.client.Set(ctx, r.prefix+key, value, ttl).Err()
}

// ... implement other methods
```

---

## Complete Integration Example

### In kube_manager (Consuming Service)

```go
package main

import (
    "context"

    // kube_manager's own infrastructure
    kubevault "github.com/victoralfred/kube_manager/pkg/vault"
    "github.com/go-redis/redis/v8"

    // shared_auth interfaces
    "github.com/victoralfred/shared_auth/cache"
    "github.com/victoralfred/shared_auth/jwt"
    "github.com/victoralfred/shared_auth/policy"
)

func main() {
    ctx := context.Background()

    // ================================================
    // STEP 1: Initialize kube_manager's infrastructure
    // ================================================

    // kube_manager's Vault client
    vaultClient, _ := kubevault.NewClient(kubevault.Config{
        Address: os.Getenv("VAULT_ADDR"),
        Token:   os.Getenv("VAULT_TOKEN"),
    })

    // kube_manager's Redis client
    redisClient := redis.NewClient(&redis.Options{
        Addr: "localhost:6379",
    })

    // ================================================
    // STEP 2: Load keys using kube_manager's Vault
    // ================================================

    publicKeyPEM, _ := vaultClient.GetSecret(ctx, "jwt")
    publicKey, _ := parsePublicKey(publicKeyPEM["public_key"].(string))

    // ================================================
    // STEP 3: Create adapters for shared_auth
    // ================================================

    // Create cache adapter
    authCache := &adapters.RedisCache{
        Client: redisClient,
        Prefix: "auth:",
    }

    // ================================================
    // STEP 4: Use shared_auth with injected dependencies
    // ================================================

    // Create JWT verifier
    verifier := jwt.NewVerifier(publicKey, "kubemanager", "my-service")

    // Create policy engine
    engine := policy.NewEngine(authCache)  // Inject cache adapter

    // Load policies
    engine.LoadPolicies(policies)

    // Use in HTTP middleware
    router.Use(middleware.AuthMiddleware(verifier))
}
```

---

## Benefits of This Architecture

### 1. **Interface Stability = No Breaking Changes**

```go
// v1.0.0
type Verifier interface {
    VerifyToken(token string) (*Claims, error)
}

type verifier struct {
    publicKey *rsa.PublicKey
}

// v2.0.0 - Implementation changes, interface unchanged!
type verifier struct {
    publicKey *rsa.PublicKey
    cache     Cache      // NEW: added caching
    metrics   Metrics    // NEW: added metrics
    logger    Logger     // NEW: added logging
}
```

**Services using v1.0.0 don't break when upgrading to v2.0.0** because the interface contract stayed the same!

---

### 2. **No Infrastructure Conflicts**

```
├── shared_auth        (NO vault dependency)  ✅
└── kube_manager/vault (v1.9.0)               ✅ Single source
```

---

### 3. **Easy Testing**

```go
// Production: Use real Redis
redisCache := &adapters.RedisCache{client: redisClient}
engine := policy.NewEngine(redisCache)

// Testing: Use mock
mockCache := cache.NewMockCache()
engine := policy.NewEngine(mockCache)
```

---

### 4. **Infrastructure Flexibility**

Want to switch from Redis to Memcached?
```go
// Just create a new adapter - shared_auth doesn't care!
type MemcachedCache struct {
    client *memcache.Client
}

func (m *MemcachedCache) Get(key string) (interface{}, bool) {
    // Implements cache.Cache interface
}

memCache := &MemcachedCache{client: memcachedClient}
engine := policy.NewEngine(memCache)  // Works!
```

---

## Migration Guide (For Existing Services)

If you were using the old shared_auth with built-in Vault/Redis:

### Step 1: Create Adapters

```go
// In your service: internal/adapters/cache.go
package adapters

import (
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

// ... implement other cache.Cache methods
```

### Step 2: Load Keys From Your Vault

```go
// Use YOUR Vault client
vaultClient, _ := vault.NewClient(vaultConfig)
publicKeyPEM, _ := vaultClient.GetSecret(ctx, "jwt/public_key")
publicKey, _ := crypto.ParsePublicKey([]byte(publicKeyPEM))
```

### Step 3: Inject Everything

```go
// Create adapters
authCache := adapters.NewRedisCache(redisClient, "auth:")

// Create shared_auth components
verifier := jwt.NewVerifier(publicKey, "kubemanager", "my-service")
engine := policy.NewEngine(authCache)
```

---

## FAQ

### Q: Why not include Redis/Vault in shared_auth?

**A:** Because different services may:
- Use different versions
- Have different configurations
- Want different implementations (Redis vs Memcached)
- Need custom connection logic (TLS, auth, etc.)

### Q: What if I want to change the internal implementation?

**A:** Go ahead! As long as you don't change the public interfaces, existing services won't break.

Example:
```go
// v1.0 - Simple implementation
type verifier struct {
    publicKey *rsa.PublicKey
}

// v2.0 - Add features (interface unchanged)
type verifier struct {
    publicKey  *rsa.PublicKey
    cache      Cache       // NEW
    rateLimiter RateLimiter // NEW
    metrics    Metrics     // NEW
}
```

Services using `jwt.Verifier` interface don't care about internal changes!

### Q: Do I have to implement all cache methods?

**A:** Yes, to satisfy the `cache.Cache` interface. But you can use composition:

```go
type RedisCache struct {
    *cache.MockCache  // Embed default implementation
    client *redis.Client
}

// Override only what you need
func (r *RedisCache) Get(key string) (interface{}, bool) {
    // Custom Redis implementation
}
```

---

## Summary

The `shared_auth` library is now a **pure abstraction library**:

✅ **Public interfaces** - Stable contracts
✅ **Private implementations** - Can change freely
✅ **Zero infrastructure** - No Redis, Vault, DB
✅ **Service-injected dependencies** - Use YOUR infrastructure
✅ **Future-proof** - Internal changes don't break clients

This follows the **Dependency Inversion Principle** and makes the library production-ready for any microservices architecture.
