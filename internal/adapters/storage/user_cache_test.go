package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	adaptercache "github.com/authplane/authserver/internal/adapters/cache"
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

// wrap fronts inner with a plain (non-expiring, unbounded) in-memory cache.
// TTL and size-bound behavior is covered by the cache package's bounded tests;
// these tests exercise the decorator's caching/invalidation logic.
func wrap(inner output.UserStore) output.UserStore {
	return WrapUserStore(inner, adaptercache.NewMemory[*Entry]())
}

func TestCachedUserStore_GetByID_CachesPositive(t *testing.T) {
	inner := &fakeUserStore{
		getByID: func(_ context.Context, id string) (*user.User, error) {
			return &user.User{ID: id}, nil
		},
	}
	c := wrap(inner)

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
	c := wrap(inner)

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
	c := wrap(inner)

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
	c := wrap(inner)

	if _, err := c.GetByID(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}
	u, err := c.GetByID(context.Background(), "u1")
	if u != nil || !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("post-Delete GetByID: got (%v, %v), want (nil, ErrUserNotFound)", u, err)
	}
}

// A read that lands while the delete is in flight must not outlive it.
// AdminService.DeleteUser deletes inside a transaction, so the row stays visible
// to other connections for the whole span: a read-through in there caches a
// positive entry, and if the invalidation already happened nothing clears it —
// the deleted user keeps being served for the full TTL. The del hook stands in
// for that concurrent read, deterministically and without goroutines.
// Pins the ordering inside Delete: the invalidation must follow inner.Delete,
// so a read that cached a positive entry mid-write is cleared rather than left.
//
// It does not pin the window that matters most. AdminService.DeleteUser runs
// Delete inside a transaction, so the real exposure is [invalidate, commit),
// and the del hook fires before the invalidation, not inside that span. Nothing
// here can reach it: the seam is one interface below the transaction. Covering
// it needs a test at the AdminService level, once invalidation can run
// post-commit at all — see Delete's godoc.
func TestCachedUserStore_Delete_InvalidatesAReadThatRacedTheWrite(t *testing.T) {
	deleted := false
	var c output.UserStore
	inner := &fakeUserStore{
		getByID: func(_ context.Context, id string) (*user.User, error) {
			if deleted {
				return nil, domain.ErrUserNotFound
			}
			return &user.User{ID: id}, nil
		},
		del: func(ctx context.Context, id string) error {
			// Mid-write: the row is still readable, so this caches a positive
			// entry, standing in for a concurrent request deterministically.
			if _, err := c.GetByID(ctx, id); err != nil {
				t.Errorf("read during delete: %v", err)
			}
			deleted = true
			return nil
		},
	}
	c = wrap(inner)

	if err := c.Delete(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}

	u, err := c.GetByID(context.Background(), "u1")
	if u != nil || !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("post-Delete GetByID: got (%v, %v), want (nil, ErrUserNotFound) — a read "+
			"that raced the delete left a positive entry behind, so the invalidation ran too early", u, err)
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
	c := wrap(inner)

	if u, _ := c.GetByID(context.Background(), "u1"); u.Email != "old@example.com" {
		t.Fatalf("primed cache: got %q", u.Email)
	}
	if err := c.Update(context.Background(), &user.User{ID: "u1", Email: "new@example.com"}); err != nil {
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

// The cached snapshot is the cache's own; callers get a copy. AdminService
// mutates what GetByID returns (u.Disable() writes Status and UpdatedAt in
// place) before Update invalidates the entry, so a shared pointer would let one
// caller's mutation reach every other reader of the same id mid-flight.
//
// GetByID copies in two independent places, so there are two tests. After a
// miss and a hit, three objects exist for one id: the one the inner store
// built, the snapshot in the cache (copied on the way IN), and what a hit
// returns (copied on the way OUT). A test that mutates what the MISS returned
// can only ever detect the copy-in, because that object was never the cached
// one — which is how the single test these replaced passed with the copy-out
// removed. Keep them separate: one test covering both hides which half broke.

// Copy-IN: what the inner store hands back must not become the cached snapshot.
// A store that retains its own object and mutates it later — an identity map, a
// pooled struct — would otherwise rewrite the cache from underneath and race
// every concurrent hit.
//
// It has to mutate the STORE's object to see that. Mutating what GetByID
// returned cannot: the caller's copy is separate either way once the miss path
// copies on the way out, which is why the earlier version of this test went
// green the moment that copy was added and stayed green with the copy-in gone.
func TestCachedUserStore_GetByID_MissDoesNotCacheTheStoresObject(t *testing.T) {
	shared := &user.User{ID: "u1", Status: user.StatusActive}
	c := wrap(&fakeUserStore{
		getByID: func(_ context.Context, _ string) (*user.User, error) { return shared, nil },
	})

	if _, err := c.GetByID(context.Background(), "u1"); err != nil { // primes the cache
		t.Fatal(err)
	}
	if disableErr := shared.Disable(); disableErr != nil { // the store mutates its own
		t.Fatalf("Disable: %v", disableErr)
	}

	fromCache, err := c.GetByID(context.Background(), "u1")
	if err != nil {
		t.Fatal(err)
	}
	if !fromCache.IsActive() {
		t.Fatalf("cached status: got %q, want %q — the cache aliases the store's object",
			fromCache.Status, user.StatusActive)
	}
}

// Copy-OUT: every hit must hand back its own object, so one caller's mutation
// reaches neither the cache nor the next caller. Both the mutated user and the
// compared ones come from hits — taking any of them from the miss would test
// the copy-in again instead.
func TestCachedUserStore_GetByID_HitReturnsItsOwnCopy(t *testing.T) {
	inner := &fakeUserStore{
		getByID: func(_ context.Context, id string) (*user.User, error) {
			return &user.User{ID: id, Status: user.StatusActive}, nil
		},
	}
	c := wrap(inner)

	if _, err := c.GetByID(context.Background(), "u1"); err != nil { // prime only
		t.Fatal(err)
	}

	first, err := c.GetByID(context.Background(), "u1") // hit
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.GetByID(context.Background(), "u1") // hit
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("two cache hits returned the same pointer; every caller is holding the cached snapshot")
	}

	if disableErr := first.Disable(); disableErr != nil {
		t.Fatalf("Disable: %v", disableErr)
	}
	third, err := c.GetByID(context.Background(), "u1") // hit, after the mutation
	if err != nil {
		t.Fatal(err)
	}
	if !third.IsActive() {
		t.Fatalf("status after another caller's Disable(): got %q, want %q — the hit handed out "+
			"the cached snapshot", third.Status, user.StatusActive)
	}

	if got := atomic.LoadInt64(&inner.calls); got != 1 {
		t.Fatalf("inner GetByID calls: got %d, want 1 — the reads above must all be cache hits", got)
	}
}

// The miss path too, against an inner store that hands out one shared object.
// The other copy tests cannot see this: fakeUserStore allocates per call, as
// sqlite and postgres do, so the object the caller receives is unshared by
// accident rather than by contract. WrapUserStore is exported and
// output.UserStore is injectable, so the guarantee has to hold for a store
// that pools or reuses — otherwise AdminService.DisableUser, which mutates
// what GetByID returned with no guard, writes straight into the store's own
// object.
func TestCachedUserStore_GetByID_MissCopiesASharedInnerObject(t *testing.T) {
	shared := &user.User{ID: "u1", Status: user.StatusActive}
	c := wrap(&fakeUserStore{
		getByID: func(_ context.Context, _ string) (*user.User, error) { return shared, nil },
	})

	fromMiss, err := c.GetByID(context.Background(), "u1")
	if err != nil {
		t.Fatal(err)
	}
	if fromMiss == shared {
		t.Fatal("the miss handed back the inner store's own object; a caller mutating it " +
			"writes into the store")
	}
	if disableErr := fromMiss.Disable(); disableErr != nil {
		t.Fatalf("Disable: %v", disableErr)
	}
	if !shared.IsActive() {
		t.Fatalf("inner store's object status: got %q, want %q — the caller's mutation reached it",
			shared.Status, user.StatusActive)
	}
}

// A store answering (nil, nil) breaks its contract. The decorator converts that
// to an error rather than forwarding the nil, because only three of the twelve
// GetByID call sites guard on a nil user while every one of them returns early
// on an error — so the conversion is what keeps UpdateUser, DisableUser,
// EnableUser and the introspection subject check from dereferencing it.
//
// It must not become ErrUserNotFound: callers report the two differently, a
// broken store at ERROR against a routine miss at WARN.
//
// And it is not cached — a broken answer is not a fact worth holding for the
// TTL, so every call reads through.
func TestCachedUserStore_GetByID_StoreReturningNoUserIsAnError(t *testing.T) {
	inner := &fakeUserStore{
		getByID: func(_ context.Context, _ string) (*user.User, error) { return nil, nil },
	}
	c := wrap(inner)

	for i := 0; i < 3; i++ {
		u, err := c.GetByID(context.Background(), "u1")
		if u != nil {
			t.Fatalf("call %d: got user %v, want nil", i, u)
		}
		if !errors.Is(err, domain.ErrStoreReturnedNoUser) {
			t.Fatalf("call %d: err = %v, want ErrStoreReturnedNoUser", i, err)
		}
		if errors.Is(err, domain.ErrUserNotFound) {
			t.Fatalf("call %d: a broken store must not be reported as a missing user", i)
		}
	}
	if got := atomic.LoadInt64(&inner.calls); got != 3 {
		t.Fatalf("inner GetByID calls: got %d, want 3 (a broken answer must not be cached)", got)
	}
}

// The point of converting rather than forwarding: callers that dereference the
// user without a nil check survive a broken store when they go through the
// decorator. AdminService.DisableUser is the sharpest of them — it does
// GetByID then u.Disable() with no guard between — so it stands in here for
// UpdateUser, EnableUser and the introspection subject check, which have the
// same shape. Reaching the assertion at all is the assertion: forwarding
// (nil, nil) panics instead of returning.
func TestCachedUserStore_BrokenStore_DoesNotPanicUnguardedCallers(t *testing.T) {
	c := wrap(&fakeUserStore{
		getByID: func(_ context.Context, _ string) (*user.User, error) { return nil, nil },
	})

	// The DisableUser shape, verbatim: fetch, then mutate with no nil check.
	disable := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panicked: %v", r)
			}
		}()
		u, getErr := c.GetByID(context.Background(), "u1")
		if getErr != nil {
			return getErr
		}
		return u.Disable()
	}

	if err := disable(); !errors.Is(err, domain.ErrStoreReturnedNoUser) {
		t.Fatalf("err = %v, want ErrStoreReturnedNoUser — an unguarded caller must get an "+
			"error to return, not a nil user to dereference", err)
	}
}

// Run under -race: the admin disable path (GetByID → mutate → Update) running
// against the session middleware's read path (GetByID → IsActive) on the same
// id. Both hit the same cache entry; neither may touch the other's user.
func TestCachedUserStore_ConcurrentMutateAndRead(t *testing.T) {
	inner := &fakeUserStore{
		getByID: func(_ context.Context, id string) (*user.User, error) {
			return &user.User{ID: id, Status: user.StatusActive}, nil
		},
		update: func(_ context.Context, _ *user.User) error { return nil },
	}
	c := WrapUserStore(inner, adaptercache.NewMemory[*Entry]())

	const goroutines = 16
	const iters = 200
	done := make(chan struct{})
	for g := 0; g < goroutines; g++ {
		go func(seed int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < iters; i++ {
				u, err := c.GetByID(context.Background(), "u1")
				if err != nil || u == nil {
					continue
				}
				if seed%2 == 0 {
					// Admin path: mutate in place, then write back.
					_ = u.Disable()
					_ = c.Update(context.Background(), u)
					continue
				}
				// Session path: read-only.
				_ = u.IsActive()
			}
		}(g)
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}
}

// userScopeKey is the context key the partition-aware test cache reads.
type userScopeKey struct{}

// userScope prefixes the cache key with a value read from the context — the
// seam an out-of-tree implementation uses to isolate callers. Partitioning
// lives in the injected cache, not in cachedUserStore.
func userScope(ctx context.Context, key string) string {
	v, _ := ctx.Value(userScopeKey{}).(string)
	return v + key
}

// scopedUserCache is an injected output.Cache[*Entry] that partitions entries
// by a context value, modeling how a partition-aware cache isolates the same
// user id across callers.
type scopedUserCache struct {
	mu sync.Mutex
	m  map[string]*Entry
}

func newScopedUserCache() *scopedUserCache {
	return &scopedUserCache{m: map[string]*Entry{}}
}

func (c *scopedUserCache) Load(ctx context.Context, key string) (*Entry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[userScope(ctx, key)], nil
}

func (c *scopedUserCache) Store(ctx context.Context, key string, v *Entry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[userScope(ctx, key)] = v
	return nil
}

func (c *scopedUserCache) Invalidate(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, userScope(ctx, key))
	return nil
}

var _ output.Cache[*Entry] = (*scopedUserCache)(nil)

// With a partition-aware injected cache, the same user id under different
// contexts is cached independently: each partition reads through once and a
// partition's entry is never served to another.
func TestCachedUserStore_ScopedCache_IsolatesByPartition(t *testing.T) {
	inner := &fakeUserStore{
		getByID: func(_ context.Context, id string) (*user.User, error) {
			return &user.User{ID: id}, nil
		},
		del: func(_ context.Context, _ string) error { return nil },
	}
	c := WrapUserStore(inner, newScopedUserCache())

	ctxA := context.WithValue(context.Background(), userScopeKey{}, "a")
	ctxB := context.WithValue(context.Background(), userScopeKey{}, "b")

	// Prime both partitions for the same id; each must read through once.
	if _, err := c.GetByID(ctxA, "u1"); err != nil {
		t.Fatalf("GetByID(A): %v", err)
	}
	if _, err := c.GetByID(ctxB, "u1"); err != nil {
		t.Fatalf("GetByID(B): %v", err)
	}
	// Re-read A — served from A's partition, no new inner call.
	if _, err := c.GetByID(ctxA, "u1"); err != nil {
		t.Fatalf("GetByID(A) #2: %v", err)
	}
	if got := atomic.LoadInt64(&inner.calls); got != 2 {
		t.Fatalf("inner GetByID calls: got %d, want 2 (one per partition)", got)
	}

	// Invalidate is partition-scoped: deleting in A leaves B's entry intact.
	if err := c.Delete(ctxA, "u1"); err != nil {
		t.Fatalf("Delete(A): %v", err)
	}
	if _, err := c.GetByID(ctxB, "u1"); err != nil {
		t.Fatalf("GetByID(B) after Delete(A): %v", err)
	}
	if got := atomic.LoadInt64(&inner.calls); got != 2 {
		t.Fatalf("inner GetByID calls: got %d, want 2 (B still cached)", got)
	}
}

// Run under -race: many goroutines reading/invalidating overlapping keys must
// not corrupt the cache or trip the race detector.
func TestCachedUserStore_ConcurrentReadsAndWrites(t *testing.T) {
	inner := &fakeUserStore{
		getByID: func(_ context.Context, id string) (*user.User, error) {
			return &user.User{ID: id}, nil
		},
		update: func(_ context.Context, _ *user.User) error { return nil },
		del:    func(_ context.Context, _ string) error { return nil },
	}
	c := WrapUserStore(inner, adaptercache.NewMemoryTTLBounded[*Entry](100*time.Millisecond, 64))

	const goroutines = 32
	const iters = 300
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
