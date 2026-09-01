package oidc

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Cache is the discovery / JWKS cache seam used by the Provider, keyed by a
// string (issuer or jwks_uri). The default is the in-memory ttlCache; an
// alternate implementation — e.g. a shared cache across instances — can be
// injected with WithDiscoveryCache / WithJWKSCache.
//
// ctx is threaded so an implementation that performs I/O (a distributed cache)
// can honor cancellation, deadlines, and tracing. The default in-memory cache
// ignores it.
type Cache[V any] interface {
	// Load returns the fresh cached value, or calls fetch once to populate it.
	Load(ctx context.Context, key string, fetch func() (V, error)) (V, error)
	// Fresh returns the value only if present and not expired.
	Fresh(ctx context.Context, key string) (V, bool)
	// Peek returns the value ignoring the TTL — it may be expired. Used for the
	// stale fallback when a refetch fails.
	Peek(ctx context.Context, key string) (V, bool)
	// Store inserts or replaces the value for key.
	Store(ctx context.Context, key string, v V)
}

var _ Cache[int] = (*ttlCache[int])(nil)

type cached[V any] struct {
	val       V
	expiresAt time.Time
}

// ttlCache is a concurrent string-keyed cache with a TTL. It keeps expired
// entries (rather than deleting them) so a caller can serve them as stale when
// a refetch fails. singleflight collapses concurrent misses into a single
// fetch — important on cold start, when many /login requests arrive at once.
//
// Entries are never evicted, only expired: the map holds one entry per distinct
// key forever. For the default single-issuer deployment that is one entry. It
// assumes a bounded set of keys (issuers / jwks_uris); a deployment that
// resolves an unbounded set of issuers should inject a size-bounded Cache via
// WithDiscoveryCache / WithJWKSCache instead.
type ttlCache[V any] struct {
	ttl      time.Duration
	maxStale time.Duration // how long past expiry Peek may still serve a value
	mu       sync.Mutex
	m        map[string]cached[V]
	sf       singleflight.Group
}

func newTTLCache[V any](ttl, maxStale time.Duration) *ttlCache[V] {
	return &ttlCache[V]{ttl: ttl, maxStale: maxStale, m: make(map[string]cached[V])}
}

// Fresh returns the cached value only if present and not expired.
func (c *ttlCache[V]) Fresh(_ context.Context, key string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || time.Now().After(e.expiresAt) {
		var zero V
		return zero, false
	}
	return e.val, true
}

// Peek returns the cached value if present and not too stale — expired by no
// more than maxStale. Used for the stale fallback when a refetch fails; the cap
// bounds how long an IdP outage can keep serving stale data (notably a JWKS
// whose key may have been revoked during the outage).
func (c *ttlCache[V]) Peek(_ context.Context, key string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || time.Now().After(e.expiresAt.Add(c.maxStale)) {
		var zero V
		return zero, false
	}
	return e.val, true
}

func (c *ttlCache[V]) Store(_ context.Context, key string, v V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = cached[V]{val: v, expiresAt: time.Now().Add(c.ttl)}
}

// Load returns the fresh cached value, or calls fetch exactly once
// (singleflight) to populate it. It applies no stale logic — that is the
// caller's decision, since the caller has the logger to report it.
func (c *ttlCache[V]) Load(ctx context.Context, key string, fetch func() (V, error)) (V, error) {
	if v, ok := c.Fresh(ctx, key); ok {
		return v, nil
	}
	res, err, _ := c.sf.Do(key, func() (any, error) {
		if v, ok := c.Fresh(ctx, key); ok { // re-check after winning the flight
			return v, nil
		}
		v, err := fetch()
		if err != nil {
			return nil, err
		}
		c.Store(ctx, key, v)
		return v, nil
	})
	if err != nil {
		var zero V
		return zero, err
	}
	return res.(V), nil
}
