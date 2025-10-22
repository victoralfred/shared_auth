package events

import "time"

// PolicyUpdateEvent represents a policy change
type PolicyUpdateEvent struct {
	Event     string                   `json:"event"`      // "policy.updated", "role.updated"
	TenantID  string                   `json:"tenant_id"`
	RoleID    string                   `json:"role_id,omitempty"`
	Resource  string                   `json:"resource,omitempty"`
	Policies  []map[string]interface{} `json:"policies,omitempty"`
	Version   string                   `json:"version"`
	Timestamp time.Time                `json:"timestamp"`
}

// UserEvent represents user-related events
type UserEvent struct {
	Event     string                 `json:"event"` // "user.created", "user.updated", "user.deleted"
	UserID    string                 `json:"user_id"`
	TenantID  string                 `json:"tenant_id"`
	Changes   map[string]interface{} `json:"changes,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// CacheInvalidateEvent represents cache invalidation event
type CacheInvalidateEvent struct {
	Event     string    `json:"event"` // "cache.invalidate"
	Keys      []string  `json:"keys"`
	Pattern   string    `json:"pattern,omitempty"`
	TenantID  string    `json:"tenant_id,omitempty"`
	UserID    string    `json:"user_id,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}
