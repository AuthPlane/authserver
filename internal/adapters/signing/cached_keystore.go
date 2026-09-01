package signing

import (
	"context"
	"log/slog"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// WrapKeyStore fronts inner with a single-slot cache of the current signing
// key, mirroring the decorator pattern of storage.WrapUserStore.
//
// LoadCurrent serves the cached key when present; Save refreshes it; the
// KeyStoreListener clears it via InvalidateCache on a key-change notification.
// LoadPrevious and ListActive pass through unchanged.
//
// The cache is injected by the caller and addressed under a single fixed key.
// The process-global default (cache.NewMemory) reproduces the in-process cache
// HAKeyStore used to keep itself; an alternate implementation can partition
// entries by a value read from the context.
func WrapKeyStore(inner output.KeyStore, cache output.Cache[*output.SigningKey], obs *observability.Provider) *CachedKeyStore {
	s := &CachedKeyStore{
		inner:  inner,
		cache:  cache,
		logger: obs.Logger.With("component", "cached-keystore"),
	}
	return s
}

// CachedKeyStore is a caching decorator over output.KeyStore.
type CachedKeyStore struct {
	inner  output.KeyStore
	cache  output.Cache[*output.SigningKey]
	logger *slog.Logger
}

const cacheKey = "current" // single-slot cache key; value is *output.SigningKey

var _ output.KeyStore = (*CachedKeyStore)(nil)

// LoadCurrent serves the cached current key, falling back to the inner store
// and populating the cache on a miss. A nil (no key) result is not cached.
func (s *CachedKeyStore) LoadCurrent(ctx context.Context) (*output.SigningKey, error) {
	if cached, _ := s.cache.Load(ctx, cacheKey); cached != nil {
		return cached, nil
	}
	key, err := s.inner.LoadCurrent(ctx)
	if err != nil {
		return nil, err
	}
	if key != nil {
		_ = s.cache.Store(ctx, cacheKey, key)
	}
	return key, nil
}

// LoadPrevious passes through to the inner store.
func (s *CachedKeyStore) LoadPrevious(ctx context.Context) (*output.SigningKey, error) {
	return s.inner.LoadPrevious(ctx)
}

// ListActive passes through to the inner store.
func (s *CachedKeyStore) ListActive(ctx context.Context) ([]*output.SigningKey, error) {
	return s.inner.ListActive(ctx)
}

// Save persists the key via the inner store and, on success, refreshes the
// cached current key.
func (s *CachedKeyStore) Save(ctx context.Context, key *output.SigningKey) error {
	if err := s.inner.Save(ctx, key); err != nil {
		return err
	}
	// The key is persisted; a cache refresh failure (only possible with an
	// out-of-tree cache) leaves the previous key cached until the next
	// invalidation/read, so surface it rather than silently serving stale.
	if err := s.cache.Store(ctx, cacheKey, key); err != nil {
		s.logger.WarnContext(ctx, "refreshing cached signing key after save failed", "error", err)
	}
	return nil
}

// InvalidateCache clears the cached current key. Called by the listener on NOTIFY.
func (s *CachedKeyStore) InvalidateCache(ctx context.Context) error {
	return s.cache.Invalidate(ctx, cacheKey)
}
