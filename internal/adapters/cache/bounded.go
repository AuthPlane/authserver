package cache

import (
	"context"
	"sync"
	"time"

	"github.com/authplane/authserver/internal/ports/output"
)

// ttlEntry is a stored value together with its expiry instant.
type ttlEntry[T any] struct {
	val       T
	expiresAt time.Time
}

// memoryTTLBounded is a keyed in-memory cache with a per-entry TTL and a maximum
// entry count. Expired entries are removed lazily on Load; when a new key is
// stored into a full cache, the entry nearest its expiry is evicted first.
// It ignores ctx (no context-based partitioning).
type memoryTTLBounded[T any] struct {
	ttl     time.Duration
	maxSize int
	now     func() time.Time

	mu sync.Mutex
	m  map[string]ttlEntry[T]
}

var _ output.Cache[any] = (*memoryTTLBounded[any])(nil)

// NewMemoryTTLBounded returns a process-global keyed in-memory cache that expires
// entries ttl after they are stored and holds at most maxSize entries, evicting
// the entry nearest its expiry when full. A ttl <= 0 disables expiry; a
// maxSize <= 0 disables the size bound.
func NewMemoryTTLBounded[T any](ttl time.Duration, maxSize int) output.Cache[T] {
	return &memoryTTLBounded[T]{
		ttl:     ttl,
		maxSize: maxSize,
		now:     time.Now,
		m:       make(map[string]ttlEntry[T]),
	}
}

// Load returns the value for key, or the zero value if absent or expired. An
// expired entry is removed.
func (c *memoryTTLBounded[T]) Load(_ context.Context, key string) (T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		var zero T
		return zero, nil
	}
	if c.ttl > 0 && c.now().After(e.expiresAt) {
		delete(c.m, key)
		var zero T
		return zero, nil
	}
	return e.val, nil
}

// Store sets the value for key, evicting the entry nearest its expiry first if a
// new key would exceed maxSize.
func (c *memoryTTLBounded[T]) Store(_ context.Context, key string, v T) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.m[key]; !exists && c.maxSize > 0 && len(c.m) >= c.maxSize {
		c.evictNearestExpiry()
	}
	c.m[key] = ttlEntry[T]{val: v, expiresAt: c.now().Add(c.ttl)}
	return nil
}

// Invalidate removes the value for key.
func (c *memoryTTLBounded[T]) Invalidate(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, key)
	return nil
}

// evictNearestExpiry removes the entry closest to expiry. Caller holds c.mu.
func (c *memoryTTLBounded[T]) evictNearestExpiry() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, e := range c.m {
		if first || e.expiresAt.Before(oldest) {
			oldestKey, oldest, first = k, e.expiresAt, false
		}
	}
	if !first {
		delete(c.m, oldestKey)
	}
}
