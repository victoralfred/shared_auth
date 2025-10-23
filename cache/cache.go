// Package cache defines the caching interface that consuming services must implement.
//
// This package provides ONLY the interface definition - no concrete implementations.
// Your service must implement this interface using your own caching infrastructure
// (Redis, Memcached, etc.).
//
// # Why This Design?
//
// This interface-based approach ensures:
//   - No infrastructure conflicts between library and consuming services
//   - Full control over your caching implementation
//   - Easy testing with mock implementations
//   - Freedom to switch cache backends without changing shared_auth usage
//
// # Implementation Guide
//
// Create an adapter in your service that implements this interface:
//
//	package adapters
//
//	import (
//	    "context"
//	    "encoding/json"
//	    "time"
//
//	    "github.com/go-redis/redis/v8"
//	    "github.com/victoralfred/shared_auth/cache"
//	)
//
//	type RedisCache struct {
//	    client *redis.Client
//	    prefix string
//	}
//
//	func NewRedisCache(client *redis.Client, prefix string) cache.Cache {
//	    return &RedisCache{
//	        client: client,
//	        prefix: prefix,
//	    }
//	}
//
//	func (r *RedisCache) Get(key string) (interface{}, bool) {
//	    val, err := r.client.Get(context.Background(), r.prefix+key).Result()
//	    if err != nil {
//	        return nil, false
//	    }
//	    var result interface{}
//	    json.Unmarshal([]byte(val), &result)
//	    return result, true
//	}
//
//	func (r *RedisCache) Set(key string, value interface{}, ttl time.Duration) error {
//	    data, _ := json.Marshal(value)
//	    return r.client.Set(context.Background(), r.prefix+key, data, ttl).Err()
//	}
//
//	func (r *RedisCache) Delete(key string) error {
//	    return r.client.Del(context.Background(), r.prefix+key).Err()
//	}
//
//	func (r *RedisCache) DeletePattern(pattern string) error {
//	    iter := r.client.Scan(context.Background(), 0, r.prefix+pattern, 0).Iterator()
//	    keys := []string{}
//	    for iter.Next(context.Background()) {
//	        keys = append(keys, iter.Val())
//	    }
//	    if len(keys) > 0 {
//	        return r.client.Del(context.Background(), keys...).Err()
//	    }
//	    return nil
//	}
//
//	func (r *RedisCache) Exists(key string) bool {
//	    count, _ := r.client.Exists(context.Background(), r.prefix+key).Result()
//	    return count > 0
//	}
//
//	func (r *RedisCache) Size() int {
//	    count, _ := r.client.DBSize(context.Background()).Result()
//	    return int(count)
//	}
//
//	func (r *RedisCache) HitRate() float64 {
//	    // Optional: implement cache hit rate tracking
//	    return 0.0
//	}
//
//	func (r *RedisCache) Clear() error {
//	    return r.client.FlushDB(context.Background()).Err()
//	}
//
// # Usage with Policy Engine
//
// Once implemented, inject your cache into the policy engine:
//
//	redisClient := redis.NewClient(&redis.Options{
//	    Addr: "localhost:6379",
//	})
//
//	authCache := adapters.NewRedisCache(redisClient, "auth:")
//	policyEngine := policy.NewEngine(authCache)
//
// # Testing
//
// For testing, use the provided mock implementation:
//
//	import "github.com/victoralfred/shared_auth/cache"
//
//	func TestMyService(t *testing.T) {
//	    mockCache := cache.NewMockCache()
//	    engine := policy.NewEngine(mockCache)
//	    // Run tests...
//	}
//
// # Alternative Implementations
//
// You can implement this interface with any cache backend:
//
//	// Memcached example
//	type MemcachedCache struct {
//	    client *memcache.Client
//	}
//
//	func (m *MemcachedCache) Get(key string) (interface{}, bool) {
//	    item, err := m.client.Get(key)
//	    if err != nil {
//	        return nil, false
//	    }
//	    return item.Value, true
//	}
//	// ... implement other methods
//
//	// In-memory example (for development/testing)
//	type MemoryCache struct {
//	    data sync.Map
//	}
//
//	func (m *MemoryCache) Get(key string) (interface{}, bool) {
//	    return m.data.Load(key)
//	}
//	// ... implement other methods
package cache

import "time"

// Cache defines the caching interface that consuming services must implement.
//
// All cache keys used by shared_auth components will be passed to these methods.
// Your implementation should handle key prefixing, serialization, and connection
// management according to your infrastructure requirements.
type Cache interface {
	// Get retrieves a value from cache by key.
	// Returns the value and true if found, nil and false otherwise.
	Get(key string) (interface{}, bool)

	// Set stores a value in cache with the specified TTL.
	// A TTL of 0 means no expiration.
	Set(key string, value interface{}, ttl time.Duration) error

	// Delete removes a single key from cache.
	Delete(key string) error

	// DeletePattern removes all keys matching the given pattern.
	// Pattern syntax depends on your cache implementation (e.g., Redis glob patterns).
	DeletePattern(pattern string) error

	// Exists checks if a key exists in cache.
	Exists(key string) bool

	// Size returns the total number of items in cache.
	// This is optional - return 0 if not supported by your cache.
	Size() int

	// HitRate returns the cache hit rate as a percentage (0.0 to 1.0).
	// This is optional - return 0.0 if not supported by your cache.
	HitRate() float64

	// Clear removes all items from cache.
	// Use with caution - this affects all cached data.
	Clear() error
}
