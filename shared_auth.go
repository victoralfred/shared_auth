// Package shared_auth provides a production-ready authentication and authorization
// library for Go microservices following interface-based design principles.
//
// Architecture Philosophy
//
// This library is designed as a pure abstraction - it provides interfaces and
// business logic, but NO infrastructure implementation. Your service provides
// its own Redis, Vault, and other infrastructure components.
//
// Key Principles:
//   - Public Interfaces, Private Implementations - Depend only on stable contracts
//   - Zero Infrastructure Dependencies - No Redis, Vault, or database clients
//   - Service-Provided Infrastructure - You implement interfaces using YOUR infrastructure
//   - Future-Proof - Internal changes won't break your services
//
// Features:
//   - Stateless JWT Verification - Pure cryptographic signature validation
//   - Policy Engine - Local RBAC/ABAC evaluation without database queries
//   - Embedded Permissions - JWT tokens contain all user permissions
//   - Multi-tenant Support - Tenant-scoped policies and permissions
//   - Interface-Based - Stable public contracts, flexible implementations
//   - Zero Infrastructure - Bring your own Redis, Vault, etc.
//
// Getting Started
//
// Import the subpackages you need:
//
//	import (
//	    "github.com/victoralfred/shared_auth/jwt"
//	    "github.com/victoralfred/shared_auth/policy"
//	    "github.com/victoralfred/shared_auth/middleware"
//	    "github.com/victoralfred/shared_auth/cache"
//	    "github.com/victoralfred/shared_auth/crypto"
//	)
//
// Step 1: Implement the cache.Cache interface using your Redis client
// Step 2: Load JWT keys from your Vault
// Step 3: Initialize components and use them in your service
//
// See README.md for complete examples and usage instructions.
package shared_auth

// Version is the current version of the shared_auth library
const Version = "v1.0.1"