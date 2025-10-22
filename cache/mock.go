package cache

import (
	"sync"
	"time"
)

// MockCache provides an in-memory cache implementation for testing.
// It implements the Cache interface without requiring external infrastructure.
type MockCache struct {
	data map[string]mockItem
	mu   sync.RWMutex
}

type mockItem struct {
	value     interface{}
	expiresAt time.Time
}

// NewMockCache creates a new mock cache for testing.
func NewMockCache() *MockCache {
	return &MockCache{
		data: make(map[string]mockItem),
	}
}

// Get retrieves a value from the cache.
func (m *MockCache) Get(key string) (interface{}, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	item, exists := m.data[key]
	if !exists {
		return nil, false
	}

	// Check expiration
	if !item.expiresAt.IsZero() && time.Now().After(item.expiresAt) {
		return nil, false
	}

	return item.value, true
}

// Set stores a value in the cache with TTL.
func (m *MockCache) Set(key string, value interface{}, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}

	m.data[key] = mockItem{
		value:     value,
		expiresAt: expiresAt,
	}

	return nil
}

// Delete removes a value from the cache.
func (m *MockCache) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.data, key)
	return nil
}

// DeletePattern removes all keys matching the pattern.
// For mock implementation, * is treated as wildcard.
func (m *MockCache) DeletePattern(pattern string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Simple pattern matching - just check if key contains pattern (without *)
	searchPattern := pattern
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		searchPattern = pattern[:len(pattern)-1]
	}

	keysToDelete := []string{}
	for key := range m.data {
		if len(searchPattern) == 0 || contains(key, searchPattern) {
			keysToDelete = append(keysToDelete, key)
		}
	}

	for _, key := range keysToDelete {
		delete(m.data, key)
	}

	return nil
}

// Exists checks if a key exists in the cache.
func (m *MockCache) Exists(key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	item, exists := m.data[key]
	if !exists {
		return false
	}

	// Check expiration
	if !item.expiresAt.IsZero() && time.Now().After(item.expiresAt) {
		return false
	}

	return true
}

// Size returns the number of items in the cache.
func (m *MockCache) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.data)
}

// HitRate returns 0.0 for mock implementation.
func (m *MockCache) HitRate() float64 {
	return 0.0
}

// Clear removes all items from the cache.
func (m *MockCache) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.data = make(map[string]mockItem)
	return nil
}

// contains checks if s contains substr
func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
