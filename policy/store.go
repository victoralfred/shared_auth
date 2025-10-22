package policy

import (
	"sort"
	"sync"
)

// PolicyStore manages in-memory policy storage
type PolicyStore struct {
	policies   map[string]Policy   // policy_id -> Policy
	byTenant   map[string][]string // tenant_id -> policy_ids
	byResource map[string][]string // resource -> policy_ids
	mu         sync.RWMutex
}

// NewPolicyStore creates a new policy store
func NewPolicyStore() *PolicyStore {
	return &PolicyStore{
		policies:   make(map[string]Policy),
		byTenant:   make(map[string][]string),
		byResource: make(map[string][]string),
	}
}

// BulkLoad loads multiple policies
func (s *PolicyStore) BulkLoad(policies []Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, policy := range policies {
		s.addPolicy(policy)
	}

	return nil
}

// Update updates policies (replace or add)
func (s *PolicyStore) Update(policies []Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, policy := range policies {
		// Remove old version if exists
		if old, exists := s.policies[policy.ID]; exists {
			s.removePolicy(old)
		}
		// Add new version
		s.addPolicy(policy)
	}

	return nil
}

// GetForResource returns policies for a resource and tenant
func (s *PolicyStore) GetForResource(resource, tenantID string) []Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []Policy

	// Get policies for this resource
	policyIDs := s.byResource[resource]

	for _, policyID := range policyIDs {
		policy := s.policies[policyID]

		// Filter by tenant
		if policy.TenantID == tenantID {
			result = append(result, policy)
		}
	}

	// Sort by priority (higher first)
	sort.Slice(result, func(i, j int) bool {
		return result[i].Priority > result[j].Priority
	})

	return result
}

// Count returns total number of policies
func (s *PolicyStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.policies)
}

// addPolicy adds policy to all indexes (must be called with lock held)
func (s *PolicyStore) addPolicy(policy Policy) {
	s.policies[policy.ID] = policy

	// Index by tenant
	s.byTenant[policy.TenantID] = append(s.byTenant[policy.TenantID], policy.ID)

	// Index by resource
	s.byResource[policy.Resource] = append(s.byResource[policy.Resource], policy.ID)
}

// removePolicy removes policy from all indexes (must be called with lock held)
func (s *PolicyStore) removePolicy(policy Policy) {
	delete(s.policies, policy.ID)

	// Remove from tenant index
	s.byTenant[policy.TenantID] = removeFromSlice(s.byTenant[policy.TenantID], policy.ID)

	// Remove from resource index
	s.byResource[policy.Resource] = removeFromSlice(s.byResource[policy.Resource], policy.ID)
}

// removeFromSlice removes element from slice
func removeFromSlice(slice []string, element string) []string {
	for i, v := range slice {
		if v == element {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}
