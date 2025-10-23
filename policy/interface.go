// Package policy provides a local policy engine for RBAC/ABAC permission evaluation.
//
// This package enables fast, local permission checking without database queries.
// Policies are loaded into memory and evaluated using roles and optional ABAC
// conditions. Results are cached for improved performance.
//
// # Features
//
//   - Role-Based Access Control (RBAC)
//   - Attribute-Based Access Control (ABAC) with conditions
//   - Multi-tenant policy support
//   - Local evaluation (no database queries)
//   - Cached decision results
//   - Policy hot-reloading via events
//   - Flexible priority system for policy conflicts
//
// # Quick Start
//
// Create a policy engine and evaluate permissions:
//
//	import (
//	    "context"
//	    "github.com/victoralfred/shared_auth/policy"
//	    "github.com/victoralfred/shared_auth/cache"
//	)
//
//	// Create engine with your cache implementation
//	engine := policy.NewEngine(yourCache)
//
//	// Define policies
//	policies := []policy.Policy{
//	    {
//	        ID:       "customer-read-orders",
//	        TenantID: "*",
//	        Resource: "orders",
//	        Actions:  []string{"read"},
//	        Roles:    []string{"customer"},
//	    },
//	    {
//	        ID:       "manager-full-orders",
//	        TenantID: "*",
//	        Resource: "orders",
//	        Actions:  []string{"*"},
//	        Roles:    []string{"manager", "admin"},
//	    },
//	}
//
//	// Load policies into engine
//	engine.LoadPolicies(policies)
//
//	// Check permission
//	decision, err := engine.CheckPermission(ctx, policy.PermissionRequest{
//	    UserID:   "user-123",
//	    TenantID: "tenant-456",
//	    Roles:    []string{"customer"},
//	    Resource: "orders",
//	    Action:   "read",
//	})
//
//	if decision.Allowed {
//	    // Permission granted
//	}
//
// # Policy Structure
//
// Policies define what actions users can perform on resources:
//
//	type Policy struct {
//	    ID         string       // Unique policy identifier
//	    TenantID   string       // Tenant scope ("*" for all tenants)
//	    Resource   string       // Resource type (e.g., "orders", "users")
//	    Actions    []string     // Allowed actions (e.g., ["read", "create"] or ["*"])
//	    Roles      []string     // Required roles
//	    Conditions []Condition  // Optional ABAC conditions
//	    Priority   int          // Higher priority evaluated first
//	}
//
// # Basic RBAC Example
//
// Simple role-based access control:
//
//	policies := []policy.Policy{
//	    {
//	        ID:       "user-read-own-profile",
//	        TenantID: "*",
//	        Resource: "profiles",
//	        Actions:  []string{"read"},
//	        Roles:    []string{"user"},
//	    },
//	    {
//	        ID:       "admin-all-access",
//	        TenantID: "*",
//	        Resource: "*",
//	        Actions:  []string{"*"},
//	        Roles:    []string{"admin"},
//	    },
//	}
//
// # ABAC with Conditions
//
// Add attribute-based conditions for fine-grained control:
//
//	policy := policy.Policy{
//	    ID:       "manager-finance-reports",
//	    TenantID: "tenant-123",
//	    Resource: "reports",
//	    Actions:  []string{"read", "download"},
//	    Roles:    []string{"manager"},
//	    Conditions: []policy.Condition{
//	        {
//	            Field:    "department",
//	            Operator: "eq",
//	            Value:    "finance",
//	        },
//	    },
//	}
//
//	// When checking permission, provide context
//	decision, _ := engine.CheckPermission(ctx, policy.PermissionRequest{
//	    UserID:   "user-123",
//	    TenantID: "tenant-123",
//	    Roles:    []string{"manager"},
//	    Resource: "reports",
//	    Action:   "read",
//	    Context: map[string]interface{}{
//	        "department": "finance",  // Matches condition
//	    },
//	})
//
// # Supported Condition Operators
//
//   - "eq" - Equal to
//   - "ne" - Not equal to
//   - "gt" - Greater than
//   - "lt" - Less than
//   - "in" - In array
//   - "not_in" - Not in array
//
// Example with multiple conditions:
//
//	Conditions: []policy.Condition{
//	    {Field: "department", Operator: "eq", Value: "finance"},
//	    {Field: "level", Operator: "gt", Value: 5},
//	    {Field: "regions", Operator: "in", Value: []string{"US", "EU"}},
//	}
//
// # Multi-Tenant Support
//
// Policies can be tenant-specific or global:
//
//	// Tenant-specific policy
//	tenantPolicy := policy.Policy{
//	    ID:       "tenant-specific",
//	    TenantID: "tenant-123",  // Only for tenant-123
//	    Resource: "documents",
//	    Actions:  []string{"read"},
//	    Roles:    []string{"user"},
//	}
//
//	// Global policy (all tenants)
//	globalPolicy := policy.Policy{
//	    ID:       "global-admin",
//	    TenantID: "*",  // All tenants
//	    Resource: "*",
//	    Actions:  []string{"*"},
//	    Roles:    []string{"super_admin"},
//	}
//
// # Policy Priority
//
// When multiple policies match, higher priority wins:
//
//	policies := []policy.Policy{
//	    {
//	        ID:       "deny-sensitive",
//	        Resource: "sensitive_data",
//	        Actions:  []string{},  // Empty = deny
//	        Roles:    []string{"user"},
//	        Priority: 100,  // Higher priority
//	    },
//	    {
//	        ID:       "allow-all",
//	        Resource: "*",
//	        Actions:  []string{"*"},
//	        Roles:    []string{"user"},
//	        Priority: 1,  // Lower priority
//	    },
//	}
//
// # Caching
//
// The engine caches permission decisions for performance:
//
//	// First check - evaluates and caches
//	decision, _ := engine.CheckPermission(ctx, request)
//
//	// Subsequent checks - returns cached result (very fast)
//	decision, _ := engine.CheckPermission(ctx, request)
//
//	// Invalidate cache when user permissions change
//	engine.InvalidateCache("user-123", "tenant-456")
//
// # Hot-Reloading Policies
//
// Update policies without restarting your service:
//
//	// Initial load
//	engine.LoadPolicies(initialPolicies)
//
//	// Later, reload with updated policies
//	engine.LoadPolicies(updatedPolicies)
//
//	// Or subscribe to policy updates from message broker
//	engine.SubscribeToPolicyUpdates(yourPolicyConsumer)
//
// # Engine Statistics
//
// Monitor engine performance:
//
//	stats := engine.Stats()
//	fmt.Printf("Policies loaded: %d\n", stats.PolicyCount)
//	fmt.Printf("Cached decisions: %d\n", stats.CachedItems)
//	fmt.Printf("Cache hit rate: %.2f%%\n", stats.CacheHitRate * 100)
//
// # Permission Request
//
// When checking permissions, provide all relevant information:
//
//	request := policy.PermissionRequest{
//	    UserID:   "user-123",      // Required
//	    TenantID: "tenant-456",    // Required
//	    Roles:    []string{"manager"},  // Required
//	    Resource: "orders",        // Required
//	    Action:   "create",        // Required
//	    ObjectID: "order-789",     // Optional - specific object
//	    Context: map[string]interface{}{  // Optional - for ABAC
//	        "department": "sales",
//	        "region": "US",
//	    },
//	}
//
// # Decision Response
//
// The decision includes details about why it was made:
//
//	type Decision struct {
//	    Allowed  bool                   // Permission granted or denied
//	    Reason   string                 // Why decision was made
//	    Message  string                 // Human-readable message
//	    Metadata map[string]interface{} // Additional debug/audit info
//	}
//
//	decision, _ := engine.CheckPermission(ctx, request)
//	if decision.Allowed {
//	    fmt.Printf("Granted: %s\n", decision.Reason)
//	    // Reasons: "admin_override", "policy_match", etc.
//	} else {
//	    fmt.Printf("Denied: %s\n", decision.Message)
//	}
//
// # Integration with JWT
//
// Use with JWT claims from the jwt package:
//
//	import (
//	    "github.com/victoralfred/shared_auth/jwt"
//	    "github.com/victoralfred/shared_auth/policy"
//	)
//
//	// Verify token
//	claims, _ := verifier.VerifyToken(tokenString)
//
//	// Check permission using claims
//	decision, _ := engine.CheckPermission(ctx, policy.PermissionRequest{
//	    UserID:   claims.UserID,
//	    TenantID: claims.TenantID,
//	    Roles:    claims.Roles,
//	    Resource: "orders",
//	    Action:   "create",
//	})
//
// # Performance Considerations
//
//   - Policy evaluation is local and fast (no database queries)
//   - Results are cached for repeated checks
//   - Typical evaluation time: < 1ms (cached), < 5ms (uncached)
//   - Suitable for high-throughput applications
//   - Keep number of conditions per policy reasonable (< 10)
//
// # Best Practices
//
//   - Use wildcard ("*") for admin policies
//   - Keep policies simple and composable
//   - Use priority to handle policy conflicts
//   - Invalidate cache when permissions change
//   - Monitor cache hit rate for optimization
//   - Reload policies periodically or via events
//   - Use ABAC conditions sparingly for performance
package policy

import "context"

// Engine defines the interface for policy evaluation.
//
// This is the public contract that consuming services depend on.
// The implementation details are private and can change without breaking clients.
//
// Create an engine using the factory function:
//
//	engine := policy.NewEngine(yourCacheImplementation)
//
// Then use it to load policies and check permissions:
//
//	engine.LoadPolicies(policies)
//	decision, err := engine.CheckPermission(ctx, request)
type Engine interface {
	// LoadPolicies loads policies into the engine's local store.
	//
	// This replaces any previously loaded policies. Policies are stored
	// in memory for fast evaluation. This operation is safe to call
	// multiple times for hot-reloading policies.
	//
	// Returns an error if policy validation fails.
	LoadPolicies(policies []Policy) error

	// CheckPermission evaluates a permission request against loaded policies.
	//
	// This performs local evaluation without any database queries. The process:
	//   1. Check cache for existing decision
	//   2. If not cached, evaluate policies:
	//      - Match policies by tenant, resource, and roles
	//      - Evaluate ABAC conditions if present
	//      - Apply priority rules if multiple policies match
	//   3. Cache the decision
	//   4. Return the result
	//
	// Returns a Decision indicating whether permission is granted and why.
	CheckPermission(ctx context.Context, req PermissionRequest) (*Decision, error)

	// InvalidateCache removes cached decisions for a specific user.
	//
	// Call this when a user's permissions change (role change, policy update, etc.)
	// to ensure they don't get stale cached decisions.
	//
	// Invalidates all cached decisions for the user in the specified tenant.
	InvalidateCache(userID, tenantID string) error

	// SubscribeToPolicyUpdates registers a consumer for policy update events.
	//
	// Use this to automatically reload policies when they change in your
	// central policy management system. The consumer should implement
	// PolicyUpdateConsumer interface and handle events from your message
	// broker (RabbitMQ, Kafka, etc.).
	//
	// Example:
	//   consumer := &MyRabbitMQConsumer{...}
	//   engine.SubscribeToPolicyUpdates(consumer)
	SubscribeToPolicyUpdates(consumer PolicyUpdateConsumer) error

	// Stats returns statistics about the engine's performance.
	//
	// Use this for monitoring and optimization:
	//   - PolicyCount: Number of loaded policies
	//   - CachedItems: Number of cached decisions
	//   - CacheHitRate: Percentage of cache hits (0.0 to 1.0)
	Stats() EngineStats
}

// PolicyUpdateConsumer defines the interface for consuming policy update events.
//
// Consuming services implement this interface to receive policy updates
// from their message broker (RabbitMQ, Kafka, etc.).
//
// Example implementation:
//
//	type RabbitMQConsumer struct {
//	    channel *amqp.Channel
//	}
//
//	func (r *RabbitMQConsumer) Subscribe(callback func(event PolicyUpdateEvent)) error {
//	    msgs, err := r.channel.Consume("policy_updates", "", true, false, false, false, nil)
//	    if err != nil {
//	        return err
//	    }
//
//	    go func() {
//	        for msg := range msgs {
//	            var event PolicyUpdateEvent
//	            json.Unmarshal(msg.Body, &event)
//	            callback(event)
//	        }
//	    }()
//
//	    return nil
//	}
type PolicyUpdateConsumer interface {
	// Subscribe registers a callback for policy update events.
	//
	// The callback will be invoked whenever a policy update event is received
	// from the message broker. The implementation should handle deserialization
	// and pass the event to the callback.
	Subscribe(callback func(event PolicyUpdateEvent)) error
}
