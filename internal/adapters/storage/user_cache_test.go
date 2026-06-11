package storage

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/ports/output"
)

// fakeUserStore is the minimal UserStore the cache decorator needs. Only
// GetByID, Update, and Delete are exercised; everything else is stubbed.
type fakeUserStore struct {
	getByID func(ctx context.Context, id string) (*user.User, error)
	update  func(ctx context.Context, u *user.User) error
	del     func(ctx context.Context, id string) error
	calls   int64 // # of inner GetByID calls (atomic)
}

func (s *fakeUserStore) Create(_ context.Context, _ *user.User) error { return nil }
func (s *fakeUserStore) GetByID(ctx context.Context, id string) (*user.User, error) {
	atomic.AddInt64(&s.calls, 1)
	return s.getByID(ctx, id)
}
func (s *fakeUserStore) GetByEmail(_ context.Context, _ string) (*user.User, error) {
	return nil, nil
}
func (s *fakeUserStore) GetByProviderSub(_ context.Context, _ user.Provider, _ string) (*user.User, error) {
	return nil, nil
}
func (s *fakeUserStore) Update(ctx context.Context, u *user.User) error {
	if s.update != nil {
		return s.update(ctx, u)
	}
	return nil
}
func (s *fakeUserStore) List(_ context.Context) ([]user.User, error) { return nil, nil }
func (s *fakeUserStore) Count(_ context.Context) (int, error)        { return 0, nil }
func (s *fakeUserStore) Delete(ctx context.Context, id string) error {
	if s.del != nil {
		return s.del(ctx, id)
	}
	return nil
}

var _ output.UserStore = (*fakeUserStore)(nil)

func TestCachedUserStore_GetByID_CachesPositive(t *testing.T) {
	inner := &fakeUserStore{
		getByID: func(_ context.Context, id string) (*user.User, error) {
			return &user.User{ID: id}, nil
		},
	}
	c := WrapUserStore(inner, 1*time.Hour, 16)

	for i := 0; i < 5; i++ {
		u, err := c.GetByID(context.Background(), "u1")
		if err != nil || u == nil || u.ID != "u1" {
			t.Fatalf("call %d: got (%v, %v), want (User{u1}, nil)", i, u, err)
		}
	}
	if got := atomic.LoadInt64(&inner.calls); got != 1 {
		t.Fatalf("inner GetByID calls: got %d, want 1 (cache hit expected)", got)
	}
}

func TestCachedUserStore_GetByID_CachesNotFound(t *testing.T) {
	inner := &fakeUserStore{
		getByID: func(_ context.Context, _ string) (*user.User, error) {
			return nil, domain.ErrUserNotFound
		},
	}
	c := WrapUserStore(inner, 1*time.Hour, 16)

	for i := 0; i < 5; i++ {
		u, err := c.GetByID(context.Background(), "ghost")
		if u != nil || !errors.Is(err, domain.ErrUserNotFound) {
			t.Fatalf("call %d: got (%v, %v), want (nil, ErrUserNotFound)", i, u, err)
		}
	}
	if got := atomic.LoadInt64(&inner.calls); got != 1 {
		t.Fatalf("inner GetByID calls: got %d, want 1 (negative cache expected)", got)
	}
}

func TestCachedUserStore_GetByID_DoesNotCacheTransientErrors(t *testing.T) {
	var attempts int64
	inner := &fakeUserStore{
		getByID: func(_ context.Context, _ string) (*user.User, error) {
			n := atomic.AddInt64(&attempts, 1)
			if n <= 2 {
				return nil, errors.New("transient")
			}
			return &user.User{ID: "u"}, nil
		},
	}
	c := WrapUserStore(inner, 1*time.Hour, 16)

	for i := 0; i < 2; i++ {
		if _, err := c.GetByID(context.Background(), "u"); err == nil {
			t.Fatalf("call %d: expected error", i)
		}
	}
	u, err := c.GetByID(context.Background(), "u")
	if err != nil || u == nil {
		t.Fatalf("third call: got (%v, %v), want (User, nil)", u, err)
	}
}

func TestCachedUserStore_TTLExpiry(t *testing.T) {
	inner := &fakeUserStore{
		getByID: func(_ context.Context, id string) (*user.User, error) {
			return &user.User{ID: id}, nil
		},
	}
	c := WrapUserStore(inner, 1*time.Hour, 16).(*cachedUserStore)

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	current := base
	c.now = func() time.Time { return current }

	if _, err := c.GetByID(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetByID(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&inner.calls); got != 1 {
		t.Fatalf("inner calls before expiry: got %d, want 1", got)
	}

	current = base.Add(2 * time.Hour)
	if _, err := c.GetByID(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&inner.calls); got != 2 {
		t.Fatalf("inner calls after expiry: got %d, want 2", got)
	}
}

func TestCachedUserStore_BoundedSize(t *testing.T) {
	inner := &fakeUserStore{
		getByID: func(_ context.Context, id string) (*user.User, error) {
			return &user.User{ID: id}, nil
		},
	}
	c := WrapUserStore(inner, 1*time.Hour, 4).(*cachedUserStore)

	for i := 0; i < 100; i++ {
		userID := "u-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		if _, err := c.GetByID(context.Background(), userID); err != nil {
			t.Fatal(err)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) > 4 {
		t.Fatalf("cache size: got %d, want <= 4", len(c.entries))
	}
}

func TestCachedUserStore_Delete_InvalidatesEntry(t *testing.T) {
	deleted := false
	inner := &fakeUserStore{
		getByID: func(_ context.Context, id string) (*user.User, error) {
			if deleted {
				return nil, domain.ErrUserNotFound
			}
			return &user.User{ID: id}, nil
		},
		del: func(_ context.Context, _ string) error {
			deleted = true
			return nil
		},
	}
	c := WrapUserStore(inner, 1*time.Hour, 16)

	// Prime cache with a positive entry.
	if _, err := c.GetByID(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}

	// Delete via the decorator — should invalidate the cached entry.
	if err := c.Delete(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}

	// Next read must hit the inner and observe the deletion immediately,
	// not after the TTL.
	u, err := c.GetByID(context.Background(), "u1")
	if u != nil || !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("post-Delete GetByID: got (%v, %v), want (nil, ErrUserNotFound)", u, err)
	}
}

func TestCachedUserStore_Update_InvalidatesEntry(t *testing.T) {
	current := &user.User{ID: "u1", Email: "old@example.com"}
	inner := &fakeUserStore{
		getByID: func(_ context.Context, _ string) (*user.User, error) {
			cp := *current
			return &cp, nil
		},
		update: func(_ context.Context, u *user.User) error {
			cp := *u
			current = &cp
			return nil
		},
	}
	c := WrapUserStore(inner, 1*time.Hour, 16)

	if u, _ := c.GetByID(context.Background(), "u1"); u.Email != "old@example.com" {
		t.Fatalf("primed cache: got %q", u.Email)
	}

	updated := &user.User{ID: "u1", Email: "new@example.com"}
	if err := c.Update(context.Background(), updated); err != nil {
		t.Fatal(err)
	}

	u, err := c.GetByID(context.Background(), "u1")
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "new@example.com" {
		t.Fatalf("post-Update email: got %q, want %q", u.Email, "new@example.com")
	}
}

// TestCachedUserStore_ConcurrentStampede documents the cache-stampede
// behavior: N goroutines doing the FIRST GetByID for the same key all miss
// the cache, all call the inner store, all then store. Map writes are
// serialized (no corruption) but you pay up to N DB queries during the
// window before the first store lands. Once any one stores, subsequent
// callers hit the cache and the inner call count stops growing.
//
// This is not a bug — it's an explicit design choice (no singleflight, the
// access pattern is one entry per active session so stampede is bounded by
// concurrency for a single key).
func TestCachedUserStore_ConcurrentStampede(t *testing.T) {
	const goroutines = 16
	release := make(chan struct{})
	var inflight int64

	inner := &fakeUserStore{
		getByID: func(_ context.Context, id string) (*user.User, error) {
			// Hold every caller until we've launched all goroutines, so the
			// "all miss before any stores" race window is forced open.
			atomic.AddInt64(&inflight, 1)
			<-release
			return &user.User{ID: id}, nil
		},
	}
	c := WrapUserStore(inner, 1*time.Hour, 64)

	done := make(chan struct{}, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			_, _ = c.GetByID(context.Background(), "u1")
			done <- struct{}{}
		}()
	}

	// Wait for every goroutine to be parked inside inner.GetByID, then
	// release them simultaneously.
	for atomic.LoadInt64(&inflight) < goroutines {
		time.Sleep(time.Millisecond)
	}
	close(release)
	for i := 0; i < goroutines; i++ {
		<-done
	}

	// All N goroutines missed and called inner — the documented stampede.
	if got := atomic.LoadInt64(&inner.calls); got != goroutines {
		t.Fatalf("inner calls during stampede: got %d, want %d", got, goroutines)
	}

	// After the stampede settles, follow-up reads ride the cache.
	atomic.StoreInt64(&inner.calls, 0)
	for i := 0; i < 5; i++ {
		_, _ = c.GetByID(context.Background(), "u1")
	}
	if got := atomic.LoadInt64(&inner.calls); got != 0 {
		t.Fatalf("post-stampede follow-ups: got %d inner calls, want 0", got)
	}
}

// TestCachedUserStore_ReadDeleteRace_BoundedStale documents the read-vs-write
// race: an in-flight GetByID can store a pre-delete snapshot AFTER the
// concurrent Delete's invalidate runs, leaving the cache holding a stale
// "exists" entry until the TTL expires.
//
// This is the inherent property of every per-process TTL cache that doesn't
// span the inner call with a per-key lock. The test pins the behavior so a
// future change — e.g., switching to singleflight or a generation counter —
// will trip a visible failure here, prompting a deliberate decision rather
// than a silent contract change.
func TestCachedUserStore_ReadDeleteRace_BoundedStale(t *testing.T) {
	readUnblock := make(chan struct{})
	readStarted := make(chan struct{})

	inner := &fakeUserStore{
		getByID: func(_ context.Context, id string) (*user.User, error) {
			// Signal that the read is in flight, then block until the test
			// has run Delete, so the store-after-invalidate ordering is forced.
			select {
			case readStarted <- struct{}{}:
			default:
			}
			<-readUnblock
			return &user.User{ID: id}, nil
		},
		del: func(_ context.Context, _ string) error { return nil },
	}
	c := WrapUserStore(inner, 1*time.Hour, 16)

	// Start the racing read.
	readDone := make(chan struct{})
	go func() {
		_, _ = c.GetByID(context.Background(), "u1")
		close(readDone)
	}()

	// Wait for the read to be parked inside inner.GetByID, then run Delete.
	<-readStarted
	if err := c.Delete(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}
	// Now release the read; it stores the pre-delete snapshot, racing past
	// the already-completed invalidate.
	close(readUnblock)
	<-readDone

	// The cache now holds the stale "exists" entry. Calling GetByID again
	// returns it from cache without consulting the inner store.
	innerCallsBefore := atomic.LoadInt64(&inner.calls)
	u, err := c.GetByID(context.Background(), "u1")
	if err != nil || u == nil || u.ID != "u1" {
		t.Fatalf("post-race read: got (%v, %v), want stale (User{u1}, nil)", u, err)
	}
	if got := atomic.LoadInt64(&inner.calls) - innerCallsBefore; got != 0 {
		t.Fatalf("post-race read called inner %d times, want 0 (stale cache hit)", got)
	}
	// Documented invariant: bounded by TTL. We don't wait for it here (the
	// TTL is 1h for determinism); TestCachedUserStore_TTLExpiry covers the
	// expiry leg separately.
}

// TestCachedUserStore_ConcurrentReadsAndWrites pounds the cache with many
// goroutines doing GetByID, Update, and Delete on overlapping keys. Designed
// to be run under `go test -race`: any unsynchronized map access or struct
// field write would surface here. Does not assert exact cache contents (the
// race between an in-flight read and an Update/Delete is bounded by TTL by
// design); only asserts no crashes and no race-detector hits.
func TestCachedUserStore_ConcurrentReadsAndWrites(t *testing.T) {
	inner := &fakeUserStore{
		getByID: func(_ context.Context, id string) (*user.User, error) {
			return &user.User{ID: id}, nil
		},
		update: func(_ context.Context, _ *user.User) error { return nil },
		del:    func(_ context.Context, _ string) error { return nil },
	}
	c := WrapUserStore(inner, 100*time.Millisecond, 64)

	const goroutines = 32
	const iters = 500
	keys := []string{"u1", "u2", "u3", "u4"}

	done := make(chan struct{})
	for g := 0; g < goroutines; g++ {
		go func(seed int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < iters; i++ {
				k := keys[(seed+i)%len(keys)]
				switch (seed + i) % 5 {
				case 0:
					_ = c.Update(context.Background(), &user.User{ID: k})
				case 1:
					_ = c.Delete(context.Background(), k)
				default:
					_, _ = c.GetByID(context.Background(), k)
				}
			}
		}(g)
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}
}

func TestWrapUserStore_DisabledWhenTTLZero(t *testing.T) {
	inner := &fakeUserStore{
		getByID: func(_ context.Context, id string) (*user.User, error) {
			return &user.User{ID: id}, nil
		},
	}
	if got := WrapUserStore(inner, 0, 16); got != output.UserStore(inner) {
		t.Fatalf("ttl=0 should return inner unchanged; got a wrapper")
	}
}
