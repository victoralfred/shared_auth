package jwt

import "time"

// Header represents JWT header
type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid,omitempty"`
}

// Claims represents JWT claims with embedded permissions
type Claims struct {
	// Standard JWT claims (RFC 7519)
	Subject   string `json:"sub"`           // Subject (user ID)
	Issuer    string `json:"iss"`           // Issuer
	Audience  string `json:"aud"`           // Audience
	ExpiresAt int64  `json:"exp"`           // Expiration time
	NotBefore int64  `json:"nbf"`           // Not before
	IssuedAt  int64  `json:"iat"`           // Issued at
	JWTID     string `json:"jti,omitempty"` // JWT ID

	// Custom claims
	UserID      string              `json:"user_id"`
	TenantID    string              `json:"tenant_id"`
	Email       string              `json:"email"`
	Roles       []string            `json:"roles"`
	Permissions map[string][]string `json:"permissions"` // resource -> actions
	TokenType   string              `json:"token_type"`  // "access" or "refresh"
	KeyID       string              `json:"kid,omitempty"`

	// Optional metadata
	DisplayName string `json:"display_name,omitempty"`
	AvatarURL   string `json:"avatar_url,omitempty"`
}

// HasPermission checks if claims contain a specific permission
func (c *Claims) HasPermission(resource, action string) bool {
	if c.Permissions == nil {
		return false
	}

	actions, exists := c.Permissions[resource]
	if !exists {
		return false
	}

	for _, a := range actions {
		if a == action || a == "*" {
			return true
		}
	}
	return false
}

// HasAnyPermission checks if user has any of the specified permissions
func (c *Claims) HasAnyPermission(resource string, actions []string) bool {
	for _, action := range actions {
		if c.HasPermission(resource, action) {
			return true
		}
	}
	return false
}

// HasAllPermissions checks if user has all specified permissions
func (c *Claims) HasAllPermissions(resource string, actions []string) bool {
	for _, action := range actions {
		if !c.HasPermission(resource, action) {
			return false
		}
	}
	return true
}

// HasRole checks if user has a specific role
func (c *Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRole checks if user has any of the specified roles
func (c *Claims) HasAnyRole(roles []string) bool {
	for _, role := range roles {
		if c.HasRole(role) {
			return true
		}
	}
	return false
}

// IsAdmin checks if user has admin role
func (c *Claims) IsAdmin() bool {
	return c.HasRole("admin") || c.HasRole("super_admin")
}

// IsExpired checks if token is expired
func (c *Claims) IsExpired() bool {
	return c.ExpiresAt < time.Now().Unix()
}

// IsValid checks if token is currently valid
func (c *Claims) IsValid() bool {
	now := time.Now().Unix()
	return c.NotBefore <= now && c.ExpiresAt > now
}

// GetPermissionsForResource returns all actions for a resource
func (c *Claims) GetPermissionsForResource(resource string) []string {
	if c.Permissions == nil {
		return nil
	}
	return c.Permissions[resource]
}

// GetAllResources returns all resources user has permissions for
func (c *Claims) GetAllResources() []string {
	if c.Permissions == nil {
		return nil
	}

	resources := make([]string, 0, len(c.Permissions))
	for resource := range c.Permissions {
		resources = append(resources, resource)
	}
	return resources
}
