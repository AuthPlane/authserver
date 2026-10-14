package signing

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// WrapKeyStore fronts inner with a single-slot cache of the current signing
// key, mirroring the decorator pattern of storage.WrapUserStore.
//
// LoadCurrent serves the cached key when present; Save and CreateIfAbsent
// drop it so the next read sees the stored key; the KeyStoreListener clears
// it via InvalidateCache on a key-change notification.
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

	// generation counts invalidations. A LoadCurrent that misses the cache
	// stores what it read only if no invalidation happened while it was
	// reading; otherwise a key read just before a rotation could be cached
	// after the rotation dropped the entry, and served as current.
	generation atomic.Uint64
	// mu makes the generation check and the cache write one step, and an
	// invalidation another, so an invalidation can never land between them.
	mu sync.Mutex
}

const cacheKey = "current" // single-slot cache key; value is *output.SigningKey

var _ output.KeyStore = (*CachedKeyStore)(nil)

// LoadCurrent serves the cached current key, falling back to the inner store
// and populating the cache on a miss. A nil (no key) result is not cached.
func (s *CachedKeyStore) LoadCurrent(ctx context.Context) (*output.SigningKey, error) {
	if cached, _ := s.cache.Load(ctx, cacheKey); cached != nil {
		return cached, nil
	}
	gen := s.generation.Load()
	key, err := s.inner.LoadCurrent(ctx)
	if err != nil {
		return nil, err
	}
	if key != nil {
		s.mu.Lock()
		if s.generation.Load() == gen {
			_ = s.cache.Store(ctx, cacheKey, key)
		}
		s.mu.Unlock()
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

// Save persists the key via the inner store and, on success, drops the
// cached current key. The next LoadCurrent reads the stored key: the key
// handed to Save is not necessarily what the store holds (another writer may
// have rotated since), so it is never cached as current.
func (s *CachedKeyStore) Save(ctx context.Context, key *output.SigningKey) error {
	if err := s.inner.Save(ctx, key); err != nil {
		return err
	}
	s.dropCached(ctx, "save")
	return nil
}

// CreateIfAbsent creates the first key via the inner store and drops the
// cached current key, so the next LoadCurrent reads whichever key won.
func (s *CachedKeyStore) CreateIfAbsent(ctx context.Context, key *output.SigningKey) error {
	if err := s.inner.CreateIfAbsent(ctx, key); err != nil {
		return err
	}
	s.dropCached(ctx, "create")
	return nil
}

// dropCached invalidates the cached current key after a write. A failure
// (only possible with an out-of-tree cache) would leave the old key served
// until the next invalidation, so it is surfaced rather than ignored.
func (s *CachedKeyStore) dropCached(ctx context.Context, op string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.generation.Add(1)
	if err := s.cache.Invalidate(ctx, cacheKey); err != nil {
		s.logger.WarnContext(ctx, "dropping cached signing key after "+op+" failed", "error", err)
	}
}

// InvalidateCache clears the cached current key. Called by the listener on NOTIFY.
func (s *CachedKeyStore) InvalidateCache(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.generation.Add(1)
	return s.cache.Invalidate(ctx, cacheKey)
}
