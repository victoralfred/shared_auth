package cache

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryCache_SetAndGet(t *testing.T) {
	cache := NewMemoryCache(100)

	// Set a value
	err := cache.Set("key1", "value1", 5*time.Minute)
	require.NoError(t, err)

	// Get the value
	value, found := cache.Get("key1")
	assert.True(t, found)
	assert.Equal(t, "value1", value)
}

func TestMemoryCache_GetNonExistent(t *testing.T) {
	cache := NewMemoryCache(100)

	value, found := cache.Get("nonexistent")
	assert.False(t, found)
	assert.Nil(t, value)
}

func TestMemoryCache_TTLExpiration(t *testing.T) {
	cache := NewMemoryCache(100)

	// Set value with short TTL
	err := cache.Set("key1", "value1", 100*time.Millisecond)
	require.NoError(t, err)

	// Value should exist immediately
	value, found := cache.Get("key1")
	assert.True(t, found)
	assert.Equal(t, "value1", value)

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	// Value should no longer exist
	value, found = cache.Get("key1")
	assert.False(t, found)
	assert.Nil(t, value)
}

func TestMemoryCache_UpdateExisting(t *testing.T) {
	cache := NewMemoryCache(100)

	// Set initial value
	err := cache.Set("key1", "value1", 5*time.Minute)
	require.NoError(t, err)

	// Update with new value
	err = cache.Set("key1", "value2", 5*time.Minute)
	require.NoError(t, err)

	// Get updated value
	value, found := cache.Get("key1")
	assert.True(t, found)
	assert.Equal(t, "value2", value)
}

func TestMemoryCache_LRUEviction(t *testing.T) {
	cache := NewMemoryCache(3) // Small capacity

	// Fill cache to capacity
	cache.Set("key1", "value1", 5*time.Minute)
	cache.Set("key2", "value2", 5*time.Minute)
	cache.Set("key3", "value3", 5*time.Minute)

	// Add one more item - should evict least recently used
	cache.Set("key4", "value4", 5*time.Minute)

	// key1 should be evicted (least recently used)
	_, found := cache.Get("key1")
	assert.False(t, found)

	// Others should still exist
	_, found = cache.Get("key2")
	assert.True(t, found)
	_, found = cache.Get("key3")
	assert.True(t, found)
	_, found = cache.Get("key4")
	assert.True(t, found)
}

func TestMemoryCache_LRUOrdering(t *testing.T) {
	cache := NewMemoryCache(3)

	// Fill cache
	cache.Set("key1", "value1", 5*time.Minute)
	cache.Set("key2", "value2", 5*time.Minute)
	cache.Set("key3", "value3", 5*time.Minute)

	// Access key1 (makes it most recently used)
	cache.Get("key1")

	// Add new item - should evict key2 (now least recently used)
	cache.Set("key4", "value4", 5*time.Minute)

	// key2 should be evicted
	_, found := cache.Get("key2")
	assert.False(t, found)

	// key1 should still exist (was accessed)
	_, found = cache.Get("key1")
	assert.True(t, found)
}

func TestMemoryCache_Delete(t *testing.T) {
	cache := NewMemoryCache(100)

	// Set value
	cache.Set("key1", "value1", 5*time.Minute)

	// Verify it exists
	_, found := cache.Get("key1")
	assert.True(t, found)

	// Delete it
	err := cache.Delete("key1")
	require.NoError(t, err)

	// Verify it's gone
	_, found = cache.Get("key1")
	assert.False(t, found)
}

func TestMemoryCache_DeleteNonExistent(t *testing.T) {
	cache := NewMemoryCache(100)

	// Delete non-existent key should not error
	err := cache.Delete("nonexistent")
	assert.NoError(t, err)
}

func TestMemoryCache_DeletePattern(t *testing.T) {
	cache := NewMemoryCache(100)

	// Set multiple keys with pattern
	cache.Set("user:123:profile", "data1", 5*time.Minute)
	cache.Set("user:123:settings", "data2", 5*time.Minute)
	cache.Set("user:456:profile", "data3", 5*time.Minute)
	cache.Set("product:789:info", "data4", 5*time.Minute)

	// Delete pattern
	err := cache.DeletePattern("user:123:*")
	require.NoError(t, err)

	// user:123:* keys should be deleted
	_, found := cache.Get("user:123:profile")
	assert.False(t, found)
	_, found = cache.Get("user:123:settings")
	assert.False(t, found)

	// Other keys should remain
	_, found = cache.Get("user:456:profile")
	assert.True(t, found)
	_, found = cache.Get("product:789:info")
	assert.True(t, found)
}

func TestMemoryCache_Exists(t *testing.T) {
	cache := NewMemoryCache(100)

	// Non-existent key
	exists := cache.Exists("key1")
	assert.False(t, exists)

	// Set key
	cache.Set("key1", "value1", 5*time.Minute)

	// Should exist
	exists = cache.Exists("key1")
	assert.True(t, exists)
}

func TestMemoryCache_ExistsExpired(t *testing.T) {
	cache := NewMemoryCache(100)

	// Set with short TTL
	cache.Set("key1", "value1", 100*time.Millisecond)

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Should not exist after expiration
	exists := cache.Exists("key1")
	assert.False(t, exists)
}

func TestMemoryCache_Size(t *testing.T) {
	cache := NewMemoryCache(100)

	// Empty cache
	assert.Equal(t, 0, cache.Size())

	// Add items
	cache.Set("key1", "value1", 5*time.Minute)
	assert.Equal(t, 1, cache.Size())

	cache.Set("key2", "value2", 5*time.Minute)
	assert.Equal(t, 2, cache.Size())

	// Delete item
	cache.Delete("key1")
	assert.Equal(t, 1, cache.Size())
}

func TestMemoryCache_HitRate(t *testing.T) {
	cache := NewMemoryCache(100)

	// Set some values
	cache.Set("key1", "value1", 5*time.Minute)
	cache.Set("key2", "value2", 5*time.Minute)

	// 2 hits
	cache.Get("key1")
	cache.Get("key2")

	// 2 misses
	cache.Get("key3")
	cache.Get("key4")

	// Hit rate should be 50%
	hitRate := cache.HitRate()
	assert.Equal(t, 0.5, hitRate)
}

func TestMemoryCache_Clear(t *testing.T) {
	cache := NewMemoryCache(100)

	// Add items
	cache.Set("key1", "value1", 5*time.Minute)
	cache.Set("key2", "value2", 5*time.Minute)
	cache.Set("key3", "value3", 5*time.Minute)

	assert.Equal(t, 3, cache.Size())

	// Clear cache
	err := cache.Clear()
	require.NoError(t, err)

	// Should be empty
	assert.Equal(t, 0, cache.Size())

	// Keys should not exist
	_, found := cache.Get("key1")
	assert.False(t, found)
}

func TestMemoryCache_ComplexValues(t *testing.T) {
	cache := NewMemoryCache(100)

	// Test with different value types
	type User struct {
		ID    string
		Email string
		Roles []string
	}

	user := User{
		ID:    "123",
		Email: "test@example.com",
		Roles: []string{"admin", "user"},
	}

	// Set complex value
	cache.Set("user:123", user, 5*time.Minute)

	// Get and verify
	value, found := cache.Get("user:123")
	assert.True(t, found)

	retrievedUser, ok := value.(User)
	require.True(t, ok)
	assert.Equal(t, user.ID, retrievedUser.ID)
	assert.Equal(t, user.Email, retrievedUser.Email)
	assert.Equal(t, user.Roles, retrievedUser.Roles)
}

func TestMemoryCache_ConcurrentAccess(t *testing.T) {
	cache := NewMemoryCache(100)

	// Concurrent writes
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				key := fmt.Sprintf("key:%d:%d", id, j)
				cache.Set(key, j, 5*time.Minute)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				key := fmt.Sprintf("key:%d:%d", id, j)
				cache.Get(key)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// No assertions - just testing for race conditions
}

func TestMemoryCache_RealWorldScenario(t *testing.T) {
	// Simulate caching user permissions
	cache := NewMemoryCache(1000)

	// User permissions
	type PermissionCache struct {
		UserID      string
		TenantID    string
		Permissions map[string][]string
		CachedAt    time.Time
	}

	userPerms := PermissionCache{
		UserID:   "user-123",
		TenantID: "tenant-456",
		Permissions: map[string][]string{
			"orders":   {"create", "read", "update"},
			"products": {"read"},
		},
		CachedAt: time.Now(),
	}

	// Cache user permissions
	cacheKey := fmt.Sprintf("perms:%s:%s", userPerms.UserID, userPerms.TenantID)
	err := cache.Set(cacheKey, userPerms, 5*time.Minute)
	require.NoError(t, err)

	// Retrieve from cache
	value, found := cache.Get(cacheKey)
	assert.True(t, found)

	cached, ok := value.(PermissionCache)
	require.True(t, ok)
	assert.Equal(t, userPerms.UserID, cached.UserID)
	assert.Equal(t, userPerms.Permissions, cached.Permissions)

	// Invalidate user cache on permission change
	err = cache.DeletePattern(fmt.Sprintf("perms:%s:*", userPerms.UserID))
	require.NoError(t, err)

	// Should no longer exist
	_, found = cache.Get(cacheKey)
	assert.False(t, found)
}
