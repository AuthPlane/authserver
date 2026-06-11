package storage

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/ports/output"
)

// WrapUserStore returns a UserStore that transparently fronts inner with an
// in-memory TTL cache on GetByID. All other methods pass through; Update and
// Delete invalidate the cached entry.
//
// The cache exists to protect the database: SessionMiddleware's stale-session
// check calls GetByID on every authenticated request, and without
// caching that becomes one DB query per request per session.
//
// Across multiple server instances entries decay via TTL — the same
// eventual-consistency window every per-process cache has.
//
// ttl <= 0 or maxSize <= 0 disables the cache (returns inner unchanged).
func WrapUserStore(inner output.UserStore, ttl time.Duration, maxSize int) output.UserStore {
	if ttl <= 0 || maxSize <= 0 {
		return inner
	}
	return &cachedUserStore{
		inner:   inner,
		ttl:     ttl,
		maxSize: maxSize,
		now:     time.Now,
		entries: make(map[string]userCacheEntry),
	}
}

// WithUserCache returns a DataStore whose User() method returns a cached
// UserStore (see WrapUserStore). All other DataStore methods pass through
// unchanged. ttl <= 0 or maxSize <= 0 returns ds unchanged.
func WithUserCache(ds output.DataStore, ttl time.Duration, maxSize int) output.DataStore {
	wrapped := WrapUserStore(ds.User(), ttl, maxSize)
	if wrapped == ds.User() {
		return ds
	}
	return &dsWithUserCache{DataStore: ds, users: wrapped}
}

// dsWithUserCache embeds the original DataStore and overrides User().
type dsWithUserCache struct {
	output.DataStore
	users output.UserStore
}

func (d *dsWithUserCache) User() output.UserStore { return d.users }

// Unwrap returns the wrapped DataStore so driver-specific consumers (e.g. the
// postgres_key signing-key factory, which needs the concrete *postgres.DB to
// extract its connection pool) can see through this decorator.
func (d *dsWithUserCache) Unwrap() output.DataStore { return d.DataStore }

// cachedUserStore is a transparent decorator over output.UserStore.
type cachedUserStore struct {
	inner   output.UserStore
	ttl     time.Duration
	maxSize int
	now     func() time.Time

	mu      sync.Mutex
	entries map[string]userCacheEntry
}

// userCacheEntry caches the outcome of GetByID for a single id.
// notFound=true represents a cached domain.ErrUserNotFound; otherwise
// snapshot is non-nil. Other errors are never cached.
type userCacheEntry struct {
	snapshot  *user.User
	notFound  bool
	expiresAt time.Time
}

var _ output.UserStore = (*cachedUserStore)(nil)

// GetByID short-circuits to the cache when a fresh entry exists.
func (c *cachedUserStore) GetByID(ctx context.Context, id string) (*user.User, error) {
	if e, ok := c.lookup(id); ok {
		if e.notFound {
			return nil, domain.ErrUserNotFound
		}
		return e.snapshot, nil
	}

	u, err := c.inner.GetByID(ctx, id)
	switch {
	case err == nil:
		c.store(id, userCacheEntry{snapshot: u})
		return u, nil
	case errors.Is(err, domain.ErrUserNotFound):
		c.store(id, userCacheEntry{notFound: true})
		return nil, err
	default:
		// Transient error — do not cache; let the caller decide policy.
		return nil, err
	}
}

// Update invalidates the cached entry so subsequent reads see the new row.
func (c *cachedUserStore) Update(ctx context.Context, u *user.User) error {
	err := c.inner.Update(ctx, u)
	if u != nil {
		c.invalidate(u.ID)
	}
	return err
}

// Delete invalidates the cached entry. We invalidate before checking err so a
// store that partially succeeded (rare, but possible with FK cascade rollback)
// doesn't leave behind a positive cache entry pointing at a now-missing row.
func (c *cachedUserStore) Delete(ctx context.Context, id string) error {
	c.invalidate(id)
	return c.inner.Delete(ctx, id)
}

func (c *cachedUserStore) Create(ctx context.Context, u *user.User) error {
	return c.inner.Create(ctx, u)
}

func (c *cachedUserStore) GetByEmail(ctx context.Context, email string) (*user.User, error) {
	return c.inner.GetByEmail(ctx, email)
}

func (c *cachedUserStore) GetByProviderSub(ctx context.Context, p user.Provider, sub string) (*user.User, error) {
	return c.inner.GetByProviderSub(ctx, p, sub)
}

func (c *cachedUserStore) List(ctx context.Context) ([]user.User, error) {
	return c.inner.List(ctx)
}

func (c *cachedUserStore) Count(ctx context.Context) (int, error) {
	return c.inner.Count(ctx)
}

// --- cache plumbing ---

func (c *cachedUserStore) lookup(id string) (userCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[id]
	if !ok {
		return userCacheEntry{}, false
	}
	if c.now().After(e.expiresAt) {
		delete(c.entries, id)
		return userCacheEntry{}, false
	}
	return e, true
}

func (c *cachedUserStore) store(id string, e userCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxSize {
		c.evictLocked()
	}
	e.expiresAt = c.now().Add(c.ttl)
	c.entries[id] = e
}

func (c *cachedUserStore) invalidate(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, id)
}

// evictLocked removes the entry closest to expiry. Caller holds c.mu.
func (c *cachedUserStore) evictLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, e := range c.entries {
		if first || e.expiresAt.Before(oldestTime) {
			oldestKey = k
			oldestTime = e.expiresAt
			first = false
		}
	}
	if !first {
		delete(c.entries, oldestKey)
	}
}
