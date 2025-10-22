# Shared Auth Library

> Reusable authentication and authorization library for microservices with embedded security.

[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://golang.org/dl/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Features

- **Stateless JWT Verification**: Verify tokens without database queries
- **Embedded Policy Engine**: Local permission evaluation with RBAC + ABAC support
- **Gin Middleware**: Ready-to-use authentication and authorization middleware
- **LRU Caching**: Built-in memory cache for authorization decisions
- **Event-Driven**: Subscribe to policy updates via Kafka
- **Zero Database Dependencies**: All verification happens locally
- **Multi-tenant Support**: Built-in tenant isolation

## Installation

```bash
go get github.com/victoralfred/shared_auth
```

## Quick Start

### Basic Authentication

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/victoralfred/shared_auth/crypto"
    "github.com/victoralfred/shared_auth/jwt"
    "github.com/victoralfred/shared_auth/middleware"
)

func main() {
    // Load public key
    publicKey, err := crypto.LoadPublicKeyFromFile("/secrets/jwt-public.pem")
    if err != nil {
        panic(err)
    }

    // Create JWT verifier
    verifier := jwt.NewVerifier(publicKey, "kubemanager", "my-service")

    // Setup Gin router
    router := gin.Default()

    // Apply authentication middleware
    router.Use(middleware.AuthMiddleware(verifier))

    // Protected routes
    router.GET("/profile", func(c *gin.Context) {
        claims, _ := middleware.GetClaims(c)
        c.JSON(200, gin.H{
            "user_id": claims.UserID,
            "email":   claims.Email,
        })
    })

    router.Run(":8080")
}
```

### Permission-Based Authorization

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/victoralfred/shared_auth/crypto"
    "github.com/victoralfred/shared_auth/jwt"
    "github.com/victoralfred/shared_auth/middleware"
)

func main() {
    publicKey, _ := crypto.LoadPublicKeyFromFile("/secrets/jwt-public.pem")
    verifier := jwt.NewVerifier(publicKey, "kubemanager", "order-service")

    router := gin.Default()
    router.Use(middleware.AuthMiddleware(verifier))

    // Require specific permission
    router.POST("/orders",
        middleware.RequirePermission("orders", "create"),
        createOrderHandler,
    )

    router.GET("/orders/:id",
        middleware.RequirePermission("orders", "read"),
        getOrderHandler,
    )

    router.DELETE("/orders/:id",
        middleware.RequirePermission("orders", "delete"),
        deleteOrderHandler,
    )

    router.Run(":8080")
}

func createOrderHandler(c *gin.Context) {
    claims, _ := middleware.GetClaims(c)

    // User info from token (no database lookup needed)
    order := Order{
        UserID:   claims.UserID,
        TenantID: claims.TenantID,
    }

    // ... create order logic
    c.JSON(200, order)
}
```

### Role-Based Authorization

```go
// Require admin role
router.POST("/admin/users",
    middleware.RequireAdmin(),
    createUserHandler,
)

// Require specific role
router.GET("/manager/reports",
    middleware.RequireRole("manager"),
    getReportsHandler,
)
```

### Policy Engine (Advanced)

```go
package main

import (
    "context"
    "github.com/victoralfred/shared_auth/cache"
    "github.com/victoralfred/shared_auth/policy"
)

func main() {
    // Create policy engine with local cache
    memCache := cache.NewMemoryCache(10000)
    policyEngine := policy.NewEngine(memCache)

    // Load policies (from config, API, or Kafka)
    policies := []policy.Policy{
        {
            ID:       "order-create-policy",
            TenantID: "tenant-123",
            Resource: "orders",
            Actions:  []string{"create", "read"},
            Roles:    []string{"customer", "manager"},
        },
    }
    policyEngine.LoadPolicies(policies)

    // Check permission
    req := policy.PermissionRequest{
        UserID:   "user-456",
        TenantID: "tenant-123",
        Roles:    []string{"customer"},
        Resource: "orders",
        Action:   "create",
    }

    decision, _ := policyEngine.CheckPermission(context.Background(), req)
    if decision.Allowed {
        println("Access granted:", decision.Message)
    }
}
```

## Package Overview

### `jwt/` - JWT Verification
Stateless JWT verification with RSA-256 signatures.

```go
import "github.com/victoralfred/shared_auth/jwt"

verifier := jwt.NewVerifier(publicKey, "issuer", "audience")
claims, err := verifier.VerifyToken(tokenString)
```

### `policy/` - Policy Engine
Local RBAC/ABAC evaluation without database queries.

```go
import "github.com/victoralfred/shared_auth/policy"

engine := policy.NewEngine(cache)
decision, _ := engine.CheckPermission(ctx, request)
```

### `middleware/` - Gin Middleware
Ready-to-use middleware for Gin framework.

```go
import "github.com/victoralfred/shared_auth/middleware"

router.Use(middleware.AuthMiddleware(verifier))
router.Use(middleware.TenantMiddleware())
```

### `cache/` - Caching
LRU in-memory cache for authorization decisions.

```go
import "github.com/victoralfred/shared_auth/cache"

cache := cache.NewMemoryCache(10000)
cache.Set("key", value, 5*time.Minute)
```

### `events/` - Event Pub/Sub
Kafka integration for policy synchronization.

```go
import "github.com/victoralfred/shared_auth/events"

publisher := events.NewPublisher(brokers, topic)
publisher.PublishPolicyUpdate(ctx, event)
```

### `crypto/` - Key Management
RSA key loading and management utilities.

```go
import "github.com/victoralfred/shared_auth/crypto"

publicKey, err := crypto.LoadPublicKeyFromFile(path)
```

## Architecture

```
┌─────────────────────────────────────────────┐
│           Your Microservice                  │
│  ┌───────────────────────────────────────┐  │
│  │   Gin Router                          │  │
│  │   + AuthMiddleware(verifier)          │  │
│  │   + RequirePermission("orders", "create")│  │
│  └───────────────────────────────────────┘  │
│           │                                  │
│           ▼                                  │
│  ┌───────────────────────────────────────┐  │
│  │   JWT Verifier                        │  │
│  │   (Stateless - No Database)           │  │
│  └───────────────────────────────────────┘  │
│           │                                  │
│           ▼                                  │
│  ┌───────────────────────────────────────┐  │
│  │   Policy Engine                       │  │
│  │   (Local Evaluation)                  │  │
│  │   ┌─────────────┐ ┌───────────────┐  │  │
│  │   │ Policy Store│ │ Memory Cache  │  │  │
│  │   └─────────────┘ └───────────────┘  │  │
│  └───────────────────────────────────────┘  │
│           ▲                                  │
│           │ Policy Updates via Kafka        │
└───────────┼──────────────────────────────────┘
            │
     ┌──────┴──────┐
     │    Kafka    │
     └──────┬──────┘
            │
┌───────────┴──────────────────────────────────┐
│         KubeManager (Central Auth)           │
│  ┌───────────────────────────────────────┐  │
│  │   User Management                      │  │
│  │   Token Generation (with permissions)  │  │
│  │   Policy Publishing                    │  │
│  └───────────────────────────────────────┘  │
└──────────────────────────────────────────────┘
```

## Benefits

### Performance
- **80% latency reduction**: Authorization completes in <5ms (vs 30ms+ with network calls)
- **No network overhead**: Everything verified locally
- **Cache-friendly**: LRU cache for repeated authorization checks

### Scalability
- **No bottleneck**: Each service scales independently
- **Stateless verification**: No shared state between instances
- **Horizontal scaling**: Add more instances without coordination

### Resilience
- **No single point of failure**: Services operate independently
- **Graceful degradation**: Continue with cached policies if Kafka is down
- **Fault isolation**: Auth service issues don't cascade

## Configuration

### Environment Variables

```bash
# JWT Configuration
export JWT_PUBLIC_KEY_PATH=/secrets/jwt-public.pem
export JWT_ISSUER=kubemanager
export JWT_AUDIENCE=my-service

# Kafka Configuration
export KAFKA_BROKERS=localhost:9092,localhost:9093
export KAFKA_TOPIC_POLICY_UPDATES=kubemanager.policy.updates
export KAFKA_CONSUMER_GROUP=my-service-security
```

### YAML Configuration

```yaml
auth:
  jwt:
    public_key_path: /secrets/jwt-public.pem
    issuer: kubemanager
    audience: order-service

  policy:
    cache_size: 10000
    cache_ttl: 5m

  kafka:
    brokers:
      - localhost:9092
    topics:
      policy_updates: kubemanager.policy.updates
    consumer_group: order-service-security
```

## Examples

See the [`examples/`](./examples/) directory for complete working examples:

- **[basic_auth](./examples/basic_auth)** - Simple JWT authentication
- **[embedded_service](./examples/embedded_service)** - Full microservice with embedded security
- **[policy_sync](./examples/policy_sync)** - Policy synchronization via Kafka

## Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package
go test -v ./jwt
```

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Related Projects

- [kube_manager](https://github.com/victoralfred/kube_manager) - Central authentication service
- [Order Service Example](https://github.com/victoralfred/order-service-example) - Example microservice using shared_auth

## Support

For questions or issues:
- Open an issue on [GitHub](https://github.com/victoralfred/shared_auth/issues)
- Email: voseghale1@gmail.com

---

**Made with ❤️ for microservices**
