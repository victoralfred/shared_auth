package cache

import "time"

// Cache interface for caching operations
type Cache interface {
	Get(key string) (interface{}, bool)
	Set(key string, value interface{}, ttl time.Duration) error
	Delete(key string) error
	DeletePattern(pattern string) error
	Exists(key string) bool
	Size() int
	HitRate() float64
	Clear() error
}
