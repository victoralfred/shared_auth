package policy

import "context"

// Engine defines the interface for policy evaluation.
//
// This is the public contract that consuming services depend on.
// The implementation details are private and can change without breaking clients.
//
// Usage:
//
//	// Service creates cache using its own Redis infrastructure
//	redisCache := &myRedisCache{client: redisClient}
//
//	// Create policy engine using factory function
//	engine := policy.NewEngine(redisCache)
//
//	// Load policies
//	engine.LoadPolicies(policies)
//
//	// Check permissions
//	decision, err := engine.CheckPermission(ctx, request)
type Engine interface {
	// LoadPolicies loads policies into local store
	LoadPolicies(policies []Policy) error

	// CheckPermission evaluates permission locally without database queries
	CheckPermission(ctx context.Context, req PermissionRequest) (*Decision, error)

	// InvalidateCache invalidates cached decisions for a user
	InvalidateCache(userID, tenantID string) error

	// SubscribeToPolicyUpdates subscribes to policy change events
	SubscribeToPolicyUpdates(consumer PolicyUpdateConsumer) error

	// Stats returns engine statistics
	Stats() EngineStats
}

// PolicyUpdateConsumer defines the interface for consuming policy update events.
//
// Consuming services implement this interface to receive policy updates
// from their message broker (RabbitMQ, Kafka, etc.).
type PolicyUpdateConsumer interface {
	// Subscribe registers a callback for policy update events
	Subscribe(callback func(event PolicyUpdateEvent)) error
}
