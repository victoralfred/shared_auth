# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2025-10-23

### Fixed
- **Fixed** Module import error: Added root package file `shared_auth.go` to allow `go get github.com/victoralfred/shared_auth` to work correctly
- **Fixed** Missing package documentation at module root level

### Added
- **Added** Root package documentation explaining the library's architecture and usage
- **Added** Version constant for version tracking

## [1.0.0] - 2025-10-22

### Initial Release

First stable release with interface-based architecture. This library provides pure abstractions for JWT verification and policy evaluation, allowing services to provide their own infrastructure implementations.

#### Removed
- **Removed** `vault/` package - Library no longer provides Vault client
- **Removed** `cache/redis.go` - Library no longer provides Redis implementation
- **Removed** `crypto/vault.go` - Library no longer loads keys from Vault
- **Removed** Infrastructure dependencies: `github.com/hashicorp/vault/api`, `github.com/go-redis/redis/v8`

#### Changed
- **BREAKING**: `jwt.Verifier` is now an interface (was concrete struct)
- **BREAKING**: `policy.Engine` is now an interface (was concrete struct)
- **BREAKING**: All implementations are now private (lowercase names)
- **BREAKING**: Services must implement `cache.Cache` interface using their own Redis/Memcached

#### Added
- **Added** `jwt/interface.go` - Public `Verifier` interface
- **Added** `policy/interface.go` - Public `Engine` interface
- **Added** `cache/mock.go` - Mock cache for testing (no Redis needed)
- **Added** `docs/ARCHITECTURE.md` - Comprehensive architecture guide
- **Added** Comprehensive godoc for all public interfaces

### Migration Guide

#### Before (v1.x)

```go
// Library provided infrastructure
cache := cache.NewRedisCache(cache.RedisConfig{
    Host: "localhost",
    Port: 6379,
})

publicKey, _ := crypto.LoadPublicKeyFromVault(ctx, vaultClient, "jwt", "public_key")
verifier := jwt.NewVerifier(publicKey, "kubemanager", "my-service")
```

#### After (v1.0)

```go
// 1. Implement cache.Cache using YOUR Redis
type RedisCache struct { client *redis.Client }
func (r *RedisCache) Get(key string) (interface{}, bool) { ... }
// ... implement all cache.Cache methods

// 2. Load keys from YOUR Vault
vaultClient, _ := vault.NewClient(...)  // Your vault package
publicKeyPEM, _ := vaultClient.GetSecret(ctx, "jwt")
publicKey, _ := crypto.ParsePublicKey([]byte(publicKeyPEM))

// 3. Create verifier (returns interface now)
verifier := jwt.NewVerifier(publicKey, "kubemanager", "my-service")
```

### Why This Change?

1. **No Dependency Conflicts** - Services use their own Vault/Redis versions
2. **Flexibility** - Swap Redis for Memcached easily
3. **Testability** - Inject mocks without spinning up infrastructure
4. **Future-Proof** - Internal changes don't break consuming services
5. **Clean Architecture** - Library is pure business logic, no infrastructure

### What Stays The Same?

- JWT token format and verification logic
- Policy evaluation algorithm
- Middleware API
- Claims structure
- All business logic

Only how you **create** components changes - how you **use** them stays the same!

---

## [1.0.0] - 2025-10-22

### Added
- Initial release with stateless JWT verification
- Policy engine with RBAC and ABAC support
- Embedded permissions in JWT tokens
- Gin middleware for authentication and authorization
- Multi-tenant support
- LRU cache with TTL
- RabbitMQ integration for policy synchronization
- Comprehensive test coverage (87% average)

### Features
- Stateless JWT verification with RSA-256 signatures
- Local policy evaluation without database queries
- Admin role override support
- ABAC condition evaluation (eq, ne, gt, lt, in, etc.)
- Permission and role checking middleware
- Cache invalidation on policy updates
