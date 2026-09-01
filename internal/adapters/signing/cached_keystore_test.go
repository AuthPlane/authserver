package signing_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	adaptercache "github.com/authplane/authserver/internal/adapters/cache"
	adaptersigning "github.com/authplane/authserver/internal/adapters/signing"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// fakeKeyStore is a minimal output.KeyStore for exercising the caching decorator.
type fakeKeyStore struct {
	current  *output.SigningKey
	previous *output.SigningKey
	active   []*output.SigningKey
	loadErr  error
	saveErr  error

	loadCurrentCalls int
	saveCalls        int
}

func (f *fakeKeyStore) LoadCurrent(context.Context) (*output.SigningKey, error) {
	f.loadCurrentCalls++
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	return f.current, nil
}

func (f *fakeKeyStore) LoadPrevious(context.Context) (*output.SigningKey, error) {
	return f.previous, nil
}

func (f *fakeKeyStore) ListActive(context.Context) ([]*output.SigningKey, error) {
	return f.active, nil
}

func (f *fakeKeyStore) Save(_ context.Context, key *output.SigningKey) error {
	f.saveCalls++
	if f.saveErr != nil {
		return f.saveErr
	}
	f.current = key
	return nil
}

func key(kid string) *output.SigningKey { return &output.SigningKey{KeyID: kid} }

// memoryCache is the default process-global cache used by most tests.
func memoryCache() output.Cache[*output.SigningKey] {
	return adaptercache.NewMemory[*output.SigningKey]()
}

func TestWrapKeyStore_LoadCurrent_CachesAfterFirstRead(t *testing.T) {
	inner := &fakeKeyStore{current: key("k1")}
	store := adaptersigning.WrapKeyStore(inner, memoryCache(), observability.NewNoop())
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		got, err := store.LoadCurrent(ctx)
		if err != nil {
			t.Fatalf("LoadCurrent #%d: %v", i, err)
		}
		if got.KeyID != "k1" {
			t.Fatalf("LoadCurrent #%d kid = %q, want k1", i, got.KeyID)
		}
	}
	if inner.loadCurrentCalls != 1 {
		t.Fatalf("inner LoadCurrent called %d times, want 1 (cached)", inner.loadCurrentCalls)
	}
}

func TestWrapKeyStore_LoadCurrent_NoKeyNotCached(t *testing.T) {
	inner := &fakeKeyStore{current: nil} // no key yet
	store := adaptersigning.WrapKeyStore(inner, memoryCache(), observability.NewNoop())
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		got, err := store.LoadCurrent(ctx)
		if err != nil {
			t.Fatalf("LoadCurrent #%d: %v", i, err)
		}
		if got != nil {
			t.Fatalf("LoadCurrent #%d = %v, want nil", i, got)
		}
	}
	if inner.loadCurrentCalls != 2 {
		t.Fatalf("inner LoadCurrent called %d times, want 2 (nil not cached)", inner.loadCurrentCalls)
	}
}

func TestWrapKeyStore_LoadCurrent_PropagatesError(t *testing.T) {
	sentinel := errors.New("boom")
	inner := &fakeKeyStore{loadErr: sentinel}
	store := adaptersigning.WrapKeyStore(inner, memoryCache(), observability.NewNoop())

	_, err := store.LoadCurrent(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("LoadCurrent err = %v, want %v", err, sentinel)
	}
}

func TestWrapKeyStore_Save_RefreshesCache(t *testing.T) {
	inner := &fakeKeyStore{current: key("k1")}
	store := adaptersigning.WrapKeyStore(inner, memoryCache(), observability.NewNoop())
	ctx := context.Background()

	if _, err := store.LoadCurrent(ctx); err != nil { // populate cache with k1
		t.Fatalf("LoadCurrent: %v", err)
	}
	if err := store.Save(ctx, key("k2")); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.LoadCurrent(ctx)
	if err != nil {
		t.Fatalf("LoadCurrent after Save: %v", err)
	}
	if got.KeyID != "k2" {
		t.Fatalf("cached key after Save = %q, want k2", got.KeyID)
	}
	// k1 read (1) populated cache; Save refreshed it; the read above is served
	// from cache — inner LoadCurrent must not be hit again.
	if inner.loadCurrentCalls != 1 {
		t.Fatalf("inner LoadCurrent called %d times, want 1", inner.loadCurrentCalls)
	}
}

func TestWrapKeyStore_Save_DoesNotCacheOnError(t *testing.T) {
	inner := &fakeKeyStore{current: key("k1"), saveErr: errors.New("nope")}
	store := adaptersigning.WrapKeyStore(inner, memoryCache(), observability.NewNoop())
	ctx := context.Background()

	if _, err := store.LoadCurrent(ctx); err != nil {
		t.Fatalf("LoadCurrent: %v", err)
	}
	if err := store.Save(ctx, key("k2")); err == nil {
		t.Fatal("Save: expected error, got nil")
	}
	got, _ := store.LoadCurrent(ctx)
	if got.KeyID != "k1" {
		t.Fatalf("cache after failed Save = %q, want k1 (unchanged)", got.KeyID)
	}
}

func TestWrapKeyStore_InvalidateCache_ForcesReread(t *testing.T) {
	inner := &fakeKeyStore{current: key("k1")}
	store := adaptersigning.WrapKeyStore(inner, memoryCache(), observability.NewNoop())
	ctx := context.Background()

	if _, err := store.LoadCurrent(ctx); err != nil {
		t.Fatalf("LoadCurrent: %v", err)
	}
	if err := store.InvalidateCache(ctx); err != nil {
		t.Fatalf("InvalidateCache: %v", err)
	}
	inner.current = key("k2") // simulate another pod rotating

	got, err := store.LoadCurrent(ctx)
	if err != nil {
		t.Fatalf("LoadCurrent after invalidate: %v", err)
	}
	if got.KeyID != "k2" {
		t.Fatalf("after invalidate kid = %q, want k2 (re-read from inner)", got.KeyID)
	}
	if inner.loadCurrentCalls != 2 {
		t.Fatalf("inner LoadCurrent called %d times, want 2", inner.loadCurrentCalls)
	}
}

func TestWrapKeyStore_LoadPreviousAndListActive_PassThrough(t *testing.T) {
	inner := &fakeKeyStore{previous: key("prev"), active: []*output.SigningKey{key("a"), key("b")}}
	store := adaptersigning.WrapKeyStore(inner, memoryCache(), observability.NewNoop())
	ctx := context.Background()

	prev, err := store.LoadPrevious(ctx)
	if err != nil || prev.KeyID != "prev" {
		t.Fatalf("LoadPrevious = %v, %v; want prev", prev, err)
	}
	active, err := store.ListActive(ctx)
	if err != nil || len(active) != 2 {
		t.Fatalf("ListActive len = %d, %v; want 2", len(active), err)
	}
}

// scopeCtxKey carries the partition value for scopedCache.
type scopeCtxKey struct{}

// scopedCache is an injected output.Cache that partitions its single slot by a
// value read from the context — the seam an out-of-tree implementation uses to
// keep one slot per caller. With no value the partition is "" (the default).
type scopedCache struct {
	mu sync.Mutex
	m  map[string]*output.SigningKey
}

func newScopedCache() *scopedCache { return &scopedCache{m: map[string]*output.SigningKey{}} }

func (c *scopedCache) scope(ctx context.Context) string {
	v, _ := ctx.Value(scopeCtxKey{}).(string)
	return v
}

func (c *scopedCache) Load(ctx context.Context, key string) (*output.SigningKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[c.scope(ctx)+key], nil
}

func (c *scopedCache) Store(ctx context.Context, key string, v *output.SigningKey) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[c.scope(ctx)+key] = v
	return nil
}

func (c *scopedCache) Invalidate(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, c.scope(ctx)+key)
	return nil
}

var _ output.Cache[*output.SigningKey] = (*scopedCache)(nil)

func TestWrapKeyStore_ScopedCache_IsolatesByScope(t *testing.T) {
	// inner serves a different key depending on the context partition, so a
	// leak across partitions would surface as the wrong kid.
	inner := &scopeKeyStore{byScope: map[string]*output.SigningKey{
		"a": key("key-a"),
		"b": key("key-b"),
	}}
	store := adaptersigning.WrapKeyStore(inner, newScopedCache(), observability.NewNoop())

	ctxA := context.WithValue(context.Background(), scopeCtxKey{}, "a")
	ctxB := context.WithValue(context.Background(), scopeCtxKey{}, "b")

	gotA, err := store.LoadCurrent(ctxA)
	if err != nil || gotA.KeyID != "key-a" {
		t.Fatalf("LoadCurrent(A) = %v, %v; want key-a", gotA, err)
	}
	gotB, err := store.LoadCurrent(ctxB)
	if err != nil || gotB.KeyID != "key-b" {
		t.Fatalf("LoadCurrent(B) = %v, %v; want key-b (no cross-scope leak)", gotB, err)
	}

	// Both are now cached under their own partition; re-reads hit cache only.
	if _, err := store.LoadCurrent(ctxA); err != nil {
		t.Fatalf("LoadCurrent(A) #2: %v", err)
	}
	if inner.calls["a"] != 1 || inner.calls["b"] != 1 {
		t.Fatalf("inner calls = %v, want one per scope", inner.calls)
	}
}

// scopeKeyStore returns a current key chosen by the context partition.
type scopeKeyStore struct {
	byScope map[string]*output.SigningKey
	calls   map[string]int
}

func (s *scopeKeyStore) LoadCurrent(ctx context.Context) (*output.SigningKey, error) {
	if s.calls == nil {
		s.calls = map[string]int{}
	}
	sc, _ := ctx.Value(scopeCtxKey{}).(string)
	s.calls[sc]++
	return s.byScope[sc], nil
}
func (s *scopeKeyStore) LoadPrevious(context.Context) (*output.SigningKey, error) { return nil, nil }
func (s *scopeKeyStore) ListActive(context.Context) ([]*output.SigningKey, error) { return nil, nil }
func (s *scopeKeyStore) Save(context.Context, *output.SigningKey) error           { return nil }
