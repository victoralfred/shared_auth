package policy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/victoralfred/shared_auth/cache"
)

// Engine provides local policy evaluation without database queries
type Engine struct {
	cache     cache.Cache
	evaluator *Evaluator
	policies  *PolicyStore
	mu        sync.RWMutex
}

// NewEngine creates a policy engine with local caching
func NewEngine(cacheBackend cache.Cache) *Engine {
	return &Engine{
		cache:     cacheBackend,
		evaluator: NewEvaluator(),
		policies:  NewPolicyStore(),
	}
}

// LoadPolicies loads policies into local store
// Called on startup or policy update
func (e *Engine) LoadPolicies(policies []Policy) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.policies.BulkLoad(policies)
}

// CheckPermission evaluates permission locally
// NO database queries - uses cached policies only
func (e *Engine) CheckPermission(ctx context.Context, req PermissionRequest) (*Decision, error) {
	// Check cache first
	cacheKey := e.buildCacheKey(req)

	if cached, found := e.cache.Get(cacheKey); found {
		return cached.(*Decision), nil
	}

	// Evaluate locally
	decision := e.evaluate(req)

	// Cache decision
	e.cache.Set(cacheKey, decision, 5*time.Minute)

	return decision, nil
}

// buildCacheKey creates cache key for permission request
func (e *Engine) buildCacheKey(req PermissionRequest) string {
	baseKey := fmt.Sprintf("perm:%s:%s:%s:%s",
		req.UserID, req.TenantID, req.Resource, req.Action)

	if req.ObjectID != "" {
		baseKey = fmt.Sprintf("%s:%s", baseKey, req.ObjectID)
	}

	// Include context hash for ABAC policies
	if len(req.Context) > 0 {
		contextHash := e.hashContext(req.Context)
		baseKey = fmt.Sprintf("%s:ctx:%s", baseKey, contextHash)
	}

	return baseKey
}

// hashContext creates a deterministic hash of the context map
func (e *Engine) hashContext(context map[string]interface{}) string {
	// Sort keys for deterministic JSON marshaling
	data, err := json.Marshal(context)
	if err != nil {
		// If marshaling fails, create a simple hash
		return "invalid"
	}

	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash[:8]) // Use first 8 bytes for shorter key
}

// evaluate performs local policy evaluation
func (e *Engine) evaluate(req PermissionRequest) *Decision {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Step 1: Check admin override
	if e.isAdmin(req.Roles) {
		return &Decision{
			Allowed: true,
			Reason:  "admin_override",
			Message: "Admin access granted",
			Metadata: map[string]interface{}{
				"evaluated_at": time.Now(),
			},
		}
	}

	// Step 2: Get policies for resource
	policies := e.policies.GetForResource(req.Resource, req.TenantID)
	if len(policies) == 0 {
		return &Decision{
			Allowed: false,
			Reason:  "no_policies",
			Message: fmt.Sprintf("No policies found for resource '%s'", req.Resource),
		}
	}

	// Step 3: Evaluate each policy
	for _, policy := range policies {
		// Check if user has required role
		if !e.hasRequiredRole(req.Roles, policy.Roles) {
			continue
		}

		// Check if action is allowed
		if !e.hasAction(policy.Actions, req.Action) {
			continue
		}

		// Evaluate ABAC conditions if present
		if len(policy.Conditions) > 0 {
			if !e.evaluator.EvaluateConditions(policy.Conditions, req.Context) {
				continue
			}
		}

		// Policy matched
		return &Decision{
			Allowed: true,
			Reason:  "policy_match",
			Message: fmt.Sprintf("Policy '%s' granted access", policy.ID),
			Metadata: map[string]interface{}{
				"policy_id":    policy.ID,
				"evaluated_at": time.Now(),
			},
		}
	}

	// No policy matched
	return &Decision{
		Allowed: false,
		Reason:  "no_policy_match",
		Message: "No matching policy found",
		Metadata: map[string]interface{}{
			"evaluated_policies": len(policies),
			"evaluated_at":       time.Now(),
		},
	}
}

// isAdmin checks if user has admin role
func (e *Engine) isAdmin(roles []string) bool {
	for _, role := range roles {
		if role == "admin" || role == "super_admin" {
			return true
		}
	}
	return false
}

// hasRequiredRole checks if user has any of the required roles
func (e *Engine) hasRequiredRole(userRoles, requiredRoles []string) bool {
	if len(requiredRoles) == 0 {
		return true // No role requirement
	}

	for _, required := range requiredRoles {
		for _, userRole := range userRoles {
			if userRole == required {
				return true
			}
		}
	}
	return false
}

// hasAction checks if action is in allowed actions
func (e *Engine) hasAction(allowedActions []string, action string) bool {
	for _, allowed := range allowedActions {
		if allowed == action || allowed == "*" {
			return true
		}
	}
	return false
}

// InvalidateCache invalidates cache for user
func (e *Engine) InvalidateCache(userID, tenantID string) error {
	pattern := fmt.Sprintf("perm:%s:%s:*", userID, tenantID)
	return e.cache.DeletePattern(pattern)
}

// SubscribeToPolicyUpdates subscribes to policy change events
func (e *Engine) SubscribeToPolicyUpdates(consumer PolicyUpdateConsumer) error {
	return consumer.Subscribe(func(event PolicyUpdateEvent) {
		e.mu.Lock()
		defer e.mu.Unlock()

		// Update local policies
		if err := e.policies.Update(event.Policies); err != nil {
			// Log error but don't fail
			return
		}

		// Invalidate cache for affected tenant
		pattern := fmt.Sprintf("perm:*:%s:*", event.TenantID)
		e.cache.DeletePattern(pattern)
	})
}

// Stats returns engine statistics
func (e *Engine) Stats() EngineStats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return EngineStats{
		PolicyCount:  e.policies.Count(),
		CachedItems:  e.cache.Size(),
		CacheHitRate: e.cache.HitRate(),
	}
}
