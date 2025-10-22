package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/victoralfred/shared_auth/cache"
)

func createTestPolicies() []Policy {
	return []Policy{
		{
			ID:       "policy-1",
			TenantID: "tenant-123",
			Resource: "orders",
			Actions:  []string{"create", "read", "update"},
			Roles:    []string{"manager", "sales"},
			Priority: 100,
		},
		{
			ID:       "policy-2",
			TenantID: "tenant-123",
			Resource: "orders",
			Actions:  []string{"read"},
			Roles:    []string{"customer"},
			Priority: 50,
		},
		{
			ID:       "policy-3",
			TenantID: "tenant-123",
			Resource: "products",
			Actions:  []string{"*"},
			Roles:    []string{"admin"},
			Priority: 200,
		},
		{
			ID:       "policy-4",
			TenantID: "tenant-123",
			Resource: "invoices",
			Actions:  []string{"create", "read"},
			Roles:    []string{"accountant"},
			Conditions: []Condition{
				{
					Field:    "department",
					Operator: "eq",
					Value:    "finance",
				},
			},
			Priority: 150,
		},
	}
}

func TestPolicyEngine_CheckPermission_AdminOverride(t *testing.T) {
	memCache := cache.NewMemoryCache(100)
	engine := NewEngine(memCache)

	err := engine.LoadPolicies(createTestPolicies())
	require.NoError(t, err)

	req := PermissionRequest{
		UserID:   "user-1",
		TenantID: "tenant-123",
		Roles:    []string{"admin"},
		Resource: "orders",
		Action:   "delete",
	}

	decision, err := engine.CheckPermission(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, "admin_override", decision.Reason)
}

func TestPolicyEngine_CheckPermission_SuperAdminOverride(t *testing.T) {
	memCache := cache.NewMemoryCache(100)
	engine := NewEngine(memCache)

	err := engine.LoadPolicies(createTestPolicies())
	require.NoError(t, err)

	req := PermissionRequest{
		UserID:   "user-1",
		TenantID: "tenant-123",
		Roles:    []string{"super_admin"},
		Resource: "anything",
		Action:   "anything",
	}

	decision, err := engine.CheckPermission(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, "admin_override", decision.Reason)
}

func TestPolicyEngine_CheckPermission_PolicyMatch(t *testing.T) {
	memCache := cache.NewMemoryCache(100)
	engine := NewEngine(memCache)

	err := engine.LoadPolicies(createTestPolicies())
	require.NoError(t, err)

	tests := []struct {
		name     string
		req      PermissionRequest
		allowed  bool
		reason   string
	}{
		{
			name: "manager can create orders",
			req: PermissionRequest{
				UserID:   "user-1",
				TenantID: "tenant-123",
				Roles:    []string{"manager"},
				Resource: "orders",
				Action:   "create",
			},
			allowed: true,
			reason:  "policy_match",
		},
		{
			name: "customer can read orders",
			req: PermissionRequest{
				UserID:   "user-2",
				TenantID: "tenant-123",
				Roles:    []string{"customer"},
				Resource: "orders",
				Action:   "read",
			},
			allowed: true,
			reason:  "policy_match",
		},
		{
			name: "customer cannot delete orders",
			req: PermissionRequest{
				UserID:   "user-2",
				TenantID: "tenant-123",
				Roles:    []string{"customer"},
				Resource: "orders",
				Action:   "delete",
			},
			allowed: false,
			reason:  "no_policy_match",
		},
		{
			name: "admin has wildcard access to products",
			req: PermissionRequest{
				UserID:   "user-3",
				TenantID: "tenant-123",
				Roles:    []string{"admin"},
				Resource: "products",
				Action:   "delete",
			},
			allowed: true,
			reason:  "admin_override", // admin role triggers override
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.CheckPermission(context.Background(), tt.req)
			require.NoError(t, err)
			assert.Equal(t, tt.allowed, decision.Allowed)
			assert.Equal(t, tt.reason, decision.Reason)
		})
	}
}

func TestPolicyEngine_CheckPermission_ABAC(t *testing.T) {
	memCache := cache.NewMemoryCache(100)
	engine := NewEngine(memCache)

	err := engine.LoadPolicies(createTestPolicies())
	require.NoError(t, err)

	tests := []struct {
		name    string
		req     PermissionRequest
		allowed bool
	}{
		{
			name: "accountant with correct department can create invoices",
			req: PermissionRequest{
				UserID:   "user-1",
				TenantID: "tenant-123",
				Roles:    []string{"accountant"},
				Resource: "invoices",
				Action:   "create",
				Context: map[string]interface{}{
					"department": "finance",
				},
			},
			allowed: true,
		},
		{
			name: "accountant with wrong department cannot create invoices",
			req: PermissionRequest{
				UserID:   "user-1",
				TenantID: "tenant-123",
				Roles:    []string{"accountant"},
				Resource: "invoices",
				Action:   "create",
				Context: map[string]interface{}{
					"department": "sales",
				},
			},
			allowed: false,
		},
		{
			name: "accountant without department context cannot create invoices",
			req: PermissionRequest{
				UserID:   "user-1",
				TenantID: "tenant-123",
				Roles:    []string{"accountant"},
				Resource: "invoices",
				Action:   "create",
				Context:  map[string]interface{}{},
			},
			allowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.CheckPermission(context.Background(), tt.req)
			require.NoError(t, err)
			assert.Equal(t, tt.allowed, decision.Allowed)
		})
	}
}

func TestPolicyEngine_CheckPermission_NoPolicies(t *testing.T) {
	memCache := cache.NewMemoryCache(100)
	engine := NewEngine(memCache)

	// No policies loaded

	req := PermissionRequest{
		UserID:   "user-1",
		TenantID: "tenant-123",
		Roles:    []string{"user"},
		Resource: "orders",
		Action:   "read",
	}

	decision, err := engine.CheckPermission(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
	assert.Equal(t, "no_policies", decision.Reason)
}

func TestPolicyEngine_CheckPermission_Caching(t *testing.T) {
	memCache := cache.NewMemoryCache(100)
	engine := NewEngine(memCache)

	err := engine.LoadPolicies(createTestPolicies())
	require.NoError(t, err)

	req := PermissionRequest{
		UserID:   "user-1",
		TenantID: "tenant-123",
		Roles:    []string{"manager"},
		Resource: "orders",
		Action:   "create",
	}

	// First check - cache miss
	decision1, err := engine.CheckPermission(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, decision1.Allowed)

	// Second check - cache hit
	decision2, err := engine.CheckPermission(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, decision2.Allowed)

	// Stats should show cache hit
	stats := engine.Stats()
	assert.Greater(t, stats.CacheHitRate, 0.0)
}

func TestPolicyEngine_InvalidateCache(t *testing.T) {
	memCache := cache.NewMemoryCache(100)
	engine := NewEngine(memCache)

	err := engine.LoadPolicies(createTestPolicies())
	require.NoError(t, err)

	req := PermissionRequest{
		UserID:   "user-1",
		TenantID: "tenant-123",
		Roles:    []string{"manager"},
		Resource: "orders",
		Action:   "create",
	}

	// Check permission (caches decision)
	decision, err := engine.CheckPermission(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)

	// Invalidate cache
	err = engine.InvalidateCache("user-1", "tenant-123")
	require.NoError(t, err)

	// Next check should be cache miss
	decision, err = engine.CheckPermission(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestPolicyEngine_Stats(t *testing.T) {
	memCache := cache.NewMemoryCache(100)
	engine := NewEngine(memCache)

	err := engine.LoadPolicies(createTestPolicies())
	require.NoError(t, err)

	stats := engine.Stats()
	assert.Equal(t, 4, stats.PolicyCount)
	assert.Equal(t, 0, stats.CachedItems)
}

func TestPolicyEngine_RealWorldEcommerce(t *testing.T) {
	memCache := cache.NewMemoryCache(1000)
	engine := NewEngine(memCache)

	// E-commerce policies
	policies := []Policy{
		{
			ID:       "customer-orders",
			TenantID: "acme-corp",
			Resource: "orders",
			Actions:  []string{"create", "read", "cancel"},
			Roles:    []string{"customer"},
			Conditions: []Condition{
				{
					Field:    "order_status",
					Operator: "in",
					Value:    []interface{}{"pending", "processing"},
				},
			},
			Priority: 50,
		},
		{
			ID:       "manager-full-access",
			TenantID: "acme-corp",
			Resource: "orders",
			Actions:  []string{"*"},
			Roles:    []string{"manager", "admin"},
			Priority: 100,
		},
		{
			ID:       "customer-products",
			TenantID: "acme-corp",
			Resource: "products",
			Actions:  []string{"read", "review"},
			Roles:    []string{"customer"},
			Priority: 50,
		},
	}

	err := engine.LoadPolicies(policies)
	require.NoError(t, err)

	tests := []struct {
		name     string
		req      PermissionRequest
		expected bool
	}{
		{
			name: "customer can create order",
			req: PermissionRequest{
				UserID:   "cust-123",
				TenantID: "acme-corp",
				Roles:    []string{"customer"},
				Resource: "orders",
				Action:   "create",
				Context: map[string]interface{}{
					"order_status": "pending",
				},
			},
			expected: true,
		},
		{
			name: "customer cannot cancel completed order",
			req: PermissionRequest{
				UserID:   "cust-123",
				TenantID: "acme-corp",
				Roles:    []string{"customer"},
				Resource: "orders",
				Action:   "cancel",
				Context: map[string]interface{}{
					"order_status": "completed",
				},
			},
			expected: false,
		},
		{
			name: "manager can do anything with orders",
			req: PermissionRequest{
				UserID:   "mgr-456",
				TenantID: "acme-corp",
				Roles:    []string{"manager"},
				Resource: "orders",
				Action:   "delete",
			},
			expected: true, // admin role triggers override
		},
		{
			name: "customer can review products",
			req: PermissionRequest{
				UserID:   "cust-123",
				TenantID: "acme-corp",
				Roles:    []string{"customer"},
				Resource: "products",
				Action:   "review",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.CheckPermission(context.Background(), tt.req)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, decision.Allowed, "Decision: %+v", decision)
		})
	}
}
