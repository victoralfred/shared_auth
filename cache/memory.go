package cache

import (
	"container/list"
	"strings"
	"sync"
	"time"
)

// MemoryCache implements LRU cache in memory
type MemoryCache struct {
	capacity int
	items    map[string]*list.Element
	lru      *list.List
	mu       sync.RWMutex
	hits     uint64
	misses   uint64
}

type cacheEntry struct {
	key       string
	value     interface{}
	expiresAt time.Time
}

// NewMemoryCache creates a new in-memory LRU cache
func NewMemoryCache(capacity int) *MemoryCache {
	return &MemoryCache{
		capacity: capacity,
		items:    make(map[string]*list.Element),
		lru:      list.New(),
	}
}

// Get retrieves value from cache
func (c *MemoryCache) Get(key string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	element, exists := c.items[key]
	if !exists {
		c.misses++
		return nil, false
	}

	entry := element.Value.(*cacheEntry)

	// Check expiration
	if time.Now().After(entry.expiresAt) {
		c.removeElement(element)
		c.misses++
		return nil, false
	}

	// Move to front (most recently used)
	c.lru.MoveToFront(element)
	c.hits++

	return entry.value, true
}

// Set adds value to cache
func (c *MemoryCache) Set(key string, value interface{}, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Remove existing entry
	if element, exists := c.items[key]; exists {
		c.removeElement(element)
	}

	// Add new entry
	entry := &cacheEntry{
		key:       key,
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}

	element := c.lru.PushFront(entry)
	c.items[key] = element

	// Evict if over capacity
	if c.lru.Len() > c.capacity {
		c.removeElement(c.lru.Back())
	}

	return nil
}

// Delete removes value from cache
func (c *MemoryCache) Delete(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if element, exists := c.items[key]; exists {
		c.removeElement(element)
	}

	return nil
}

// DeletePattern removes all keys matching pattern
func (c *MemoryCache) DeletePattern(pattern string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Collect keys to delete
	var toDelete []string
	for key := range c.items {
		if matchesPattern(key, pattern) {
			toDelete = append(toDelete, key)
		}
	}

	// Delete collected keys
	for _, key := range toDelete {
		if element, exists := c.items[key]; exists {
			c.removeElement(element)
		}
	}

	return nil
}

// Exists checks if key exists
func (c *MemoryCache) Exists(key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	element, exists := c.items[key]
	if !exists {
		return false
	}

	entry := element.Value.(*cacheEntry)
	return time.Now().Before(entry.expiresAt)
}

// Size returns number of items in cache
func (c *MemoryCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

// HitRate returns cache hit rate
func (c *MemoryCache) HitRate() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := c.hits + c.misses
	if total == 0 {
		return 0
	}

	return float64(c.hits) / float64(total)
}

// Clear removes all items
func (c *MemoryCache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*list.Element)
	c.lru = list.New()
	c.hits = 0
	c.misses = 0

	return nil
}

// removeElement removes element from cache (must be called with lock held)
func (c *MemoryCache) removeElement(element *list.Element) {
	entry := element.Value.(*cacheEntry)
	delete(c.items, entry.key)
	c.lru.Remove(element)
}

// matchesPattern checks if key matches pattern
// Simple wildcard matching: "perm:*:tenant:*" matches "perm:user1:tenant:123"
func matchesPattern(key, pattern string) bool {
	if pattern == "*" {
		return true
	}

	// Simple prefix matching with wildcard
	if idx := strings.Index(pattern, "*"); idx >= 0 {
		prefix := pattern[:idx]
		return strings.HasPrefix(key, prefix)
	}

	return key == pattern
}
