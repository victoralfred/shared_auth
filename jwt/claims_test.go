package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestClaims_HasPermission(t *testing.T) {
	claims := CreateTestClaims()

	tests := []struct {
		name     string
		resource string
		action   string
		want     bool
	}{
		{
			name:     "has exact permission",
			resource: "orders",
			action:   "create",
			want:     true,
		},
		{
			name:     "has wildcard permission",
			resource: "invoices",
			action:   "delete",
			want:     true,
		},
		{
			name:     "missing permission",
			resource: "orders",
			action:   "delete",
			want:     false,
		},
		{
			name:     "missing resource",
			resource: "admin",
			action:   "access",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := claims.HasPermission(tt.resource, tt.action)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClaims_HasAnyPermission(t *testing.T) {
	claims := CreateTestClaims()

	tests := []struct {
		name     string
		resource string
		actions  []string
		want     bool
	}{
		{
			name:     "has one of multiple actions",
			resource: "orders",
			actions:  []string{"create", "delete"},
			want:     true,
		},
		{
			name:     "has none of the actions",
			resource: "orders",
			actions:  []string{"delete", "archive"},
			want:     false,
		},
		{
			name:     "has all actions",
			resource: "orders",
			actions:  []string{"create", "read", "update"},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := claims.HasAnyPermission(tt.resource, tt.actions)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClaims_HasAllPermissions(t *testing.T) {
	claims := CreateTestClaims()

	tests := []struct {
		name     string
		resource string
		actions  []string
		want     bool
	}{
		{
			name:     "has all actions",
			resource: "orders",
			actions:  []string{"create", "read", "update"},
			want:     true,
		},
		{
			name:     "missing one action",
			resource: "orders",
			actions:  []string{"create", "read", "delete"},
			want:     false,
		},
		{
			name:     "wildcard covers all",
			resource: "invoices",
			actions:  []string{"create", "read", "update", "delete"},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := claims.HasAllPermissions(tt.resource, tt.actions)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClaims_HasRole(t *testing.T) {
	claims := CreateTestClaims()

	tests := []struct {
		name string
		role string
		want bool
	}{
		{
			name: "has role",
			role: "user",
			want: true,
		},
		{
			name: "missing role",
			role: "admin",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := claims.HasRole(tt.role)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClaims_HasAnyRole(t *testing.T) {
	claims := CreateTestClaims()

	tests := []struct {
		name  string
		roles []string
		want  bool
	}{
		{
			name:  "has one role",
			roles: []string{"user", "admin"},
			want:  true,
		},
		{
			name:  "has no roles",
			roles: []string{"admin", "super_admin"},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := claims.HasAnyRole(tt.roles)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClaims_IsAdmin(t *testing.T) {
	tests := []struct {
		name  string
		roles []string
		want  bool
	}{
		{
			name:  "is admin",
			roles: []string{"admin"},
			want:  true,
		},
		{
			name:  "is super_admin",
			roles: []string{"super_admin"},
			want:  true,
		},
		{
			name:  "not admin",
			roles: []string{"user", "manager"},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := CreateTestClaims()
			claims.Roles = tt.roles

			got := claims.IsAdmin()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClaims_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt int64
		want      bool
	}{
		{
			name:      "not expired",
			expiresAt: time.Now().Add(1 * time.Hour).Unix(),
			want:      false,
		},
		{
			name:      "expired",
			expiresAt: time.Now().Add(-1 * time.Hour).Unix(),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := CreateTestClaims()
			claims.ExpiresAt = tt.expiresAt

			got := claims.IsExpired()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClaims_IsValid(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		notBefore int64
		expiresAt int64
		want      bool
	}{
		{
			name:      "valid",
			notBefore: now.Add(-1 * time.Hour).Unix(),
			expiresAt: now.Add(1 * time.Hour).Unix(),
			want:      true,
		},
		{
			name:      "expired",
			notBefore: now.Add(-2 * time.Hour).Unix(),
			expiresAt: now.Add(-1 * time.Hour).Unix(),
			want:      false,
		},
		{
			name:      "not yet valid",
			notBefore: now.Add(1 * time.Hour).Unix(),
			expiresAt: now.Add(2 * time.Hour).Unix(),
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := CreateTestClaims()
			claims.NotBefore = tt.notBefore
			claims.ExpiresAt = tt.expiresAt

			got := claims.IsValid()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClaims_GetPermissionsForResource(t *testing.T) {
	claims := CreateTestClaims()

	tests := []struct {
		name     string
		resource string
		want     []string
	}{
		{
			name:     "existing resource",
			resource: "orders",
			want:     []string{"create", "read", "update"},
		},
		{
			name:     "missing resource",
			resource: "nonexistent",
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := claims.GetPermissionsForResource(tt.resource)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClaims_GetAllResources(t *testing.T) {
	claims := CreateTestClaims()

	resources := claims.GetAllResources()
	assert.Len(t, resources, 3)
	assert.Contains(t, resources, "orders")
	assert.Contains(t, resources, "products")
	assert.Contains(t, resources, "invoices")
}

func TestClaims_NilPermissions(t *testing.T) {
	claims := CreateTestClaims()
	claims.Permissions = nil

	assert.False(t, claims.HasPermission("orders", "read"))
	assert.Nil(t, claims.GetPermissionsForResource("orders"))
	assert.Nil(t, claims.GetAllResources())
}
