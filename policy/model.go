package policy

import "time"

// PermissionRequest represents a permission check request
type PermissionRequest struct {
	UserID    string
	TenantID  string
	Roles     []string               // User's roles
	Resource  string                 // Resource being accessed
	Action    string                 // Action being performed
	ObjectID  string                 // Optional: specific object ID
	Context   map[string]interface{} // Additional context for ABAC
}

// Decision represents the result of a permission check
type Decision struct {
	Allowed  bool
	Reason   string                 // "admin_override", "policy_match", "no_policy_match"
	Message  string
	Metadata map[string]interface{} // Additional info for debugging/audit
}

// Policy represents a permission policy
type Policy struct {
	ID         string
	TenantID   string
	Resource   string
	Actions    []string    // ["create", "read", "update"] or ["*"]
	Roles      []string    // Required roles
	Conditions []Condition // ABAC conditions
	Priority   int         // Higher priority evaluated first
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Condition represents an ABAC condition
type Condition struct {
	Field    string      `json:"field"`    // Field to check (e.g., "department")
	Operator string      `json:"operator"` // "eq", "ne", "gt", "lt", "in", "not_in"
	Value    interface{} `json:"value"`    // Expected value
}

// PolicyUpdateEvent represents a policy change event from Kafka
type PolicyUpdateEvent struct {
	Event     string    `json:"event"`      // "policy.updated", "policy.deleted"
	TenantID  string    `json:"tenant_id"`
	Policies  []Policy  `json:"policies"`
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
}

// PolicyUpdateConsumer interface for consuming policy updates
type PolicyUpdateConsumer interface {
	Subscribe(handler func(PolicyUpdateEvent)) error
	Unsubscribe() error
}

// EngineStats provides engine statistics
type EngineStats struct {
	PolicyCount  int
	CachedItems  int
	CacheHitRate float64
}
