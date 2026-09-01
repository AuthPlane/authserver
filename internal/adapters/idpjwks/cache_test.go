package idpjwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	adaptercache "github.com/authplane/authserver/internal/adapters/cache"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/idp"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// mockIDPStore is a simple in-memory IdP store for testing.
type mockIDPStore struct {
	idps map[string]*idp.TrustedIDP
}

func newMockIdPStore() *mockIDPStore {
	return &mockIDPStore{idps: make(map[string]*idp.TrustedIDP)}
}

func (m *mockIDPStore) Save(_ context.Context, i idp.TrustedIDP) error {
	m.idps[i.Issuer] = &i
	return nil
}

func (m *mockIDPStore) GetByID(_ context.Context, id string) (*idp.TrustedIDP, error) {
	for _, i := range m.idps {
		if i.ID == id {
			return i, nil
		}
	}
	return nil, domain.ErrIDPNotFound
}

func (m *mockIDPStore) GetByIssuer(_ context.Context, issuer string) (*idp.TrustedIDP, error) {
	i, ok := m.idps[issuer]
	if !ok {
		return nil, domain.ErrIDPNotFound
	}
	return i, nil
}

func (m *mockIDPStore) List(_ context.Context) ([]idp.TrustedIDP, error) {
	var result []idp.TrustedIDP
	for _, i := range m.idps {
		result = append(result, *i)
	}
	return result, nil
}

func (m *mockIDPStore) Delete(_ context.Context, id string) error {
	for issuer, i := range m.idps {
		if i.ID == id {
			delete(m.idps, issuer)
			return nil
		}
	}
	return domain.ErrIDPNotFound
}

var _ output.IDPStore = (*mockIDPStore)(nil)

func testJWKS(t *testing.T) (jose.JSONWebKeySet, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       &key.PublicKey,
				KeyID:     "test-kid",
				Algorithm: "ES256",
				Use:       "sig",
			},
		},
	}
	return jwks, key
}

func TestCache_GetKeys(t *testing.T) {
	jwks, _ := testJWKS(t)

	// Setup mock JWKS server.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	store := newMockIdPStore()
	_ = store.Save(context.Background(), idp.TrustedIDP{
		ID:       "test-idp",
		Name:     "Test",
		Issuer:   srv.URL,
		JWKSUri:  srv.URL + "/jwks",
		Audience: "https://authplane.example.com",
		Enabled:  true,
	})

	// Create cache with the test server's TLS client.
	obs := observability.NewNoop()
	cache := New(store, adaptercache.NewMemory[*Entry](), CacheConfig{}, obs, WithHTTPClient(srv.Client()))

	keys, err := cache.GetKeys(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("GetKeys: %v", err)
	}

	if len(keys.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys.Keys))
	}
	if keys.Keys[0].KeyID != "test-kid" {
		t.Errorf("kid = %q, want %q", keys.Keys[0].KeyID, "test-kid")
	}
}

func TestCache_CacheHit(t *testing.T) {
	jwks, _ := testJWKS(t)
	fetchCount := 0

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	store := newMockIdPStore()
	_ = store.Save(context.Background(), idp.TrustedIDP{
		ID:       "test-idp",
		Issuer:   srv.URL,
		JWKSUri:  srv.URL + "/jwks",
		Audience: "https://authplane.example.com",
		Enabled:  true,
	})

	obs := observability.NewNoop()
	cache := New(store, adaptercache.NewMemory[*Entry](), CacheConfig{}, obs, WithHTTPClient(srv.Client()))

	// First call — cache miss.
	if _, err := cache.GetKeys(context.Background(), srv.URL); err != nil {
		t.Fatalf("first GetKeys: %v", err)
	}
	// Second call — cache hit (no HTTP fetch).
	if _, err := cache.GetKeys(context.Background(), srv.URL); err != nil {
		t.Fatalf("second GetKeys: %v", err)
	}

	if fetchCount != 1 {
		t.Errorf("fetch count = %d, want 1 (cached)", fetchCount)
	}
}

func TestCache_InvalidateCache(t *testing.T) {
	jwks, _ := testJWKS(t)
	fetchCount := 0

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	store := newMockIdPStore()
	_ = store.Save(context.Background(), idp.TrustedIDP{
		ID:       "test-idp",
		Issuer:   srv.URL,
		JWKSUri:  srv.URL + "/jwks",
		Audience: "https://authplane.example.com",
		Enabled:  true,
	})

	obs := observability.NewNoop()
	cache := New(store, adaptercache.NewMemory[*Entry](), CacheConfig{}, obs, WithHTTPClient(srv.Client()))

	// First fetch.
	if _, err := cache.GetKeys(context.Background(), srv.URL); err != nil {
		t.Fatalf("first GetKeys: %v", err)
	}

	// Invalidate.
	if err := cache.InvalidateCache(context.Background(), srv.URL); err != nil {
		t.Fatalf("InvalidateCache: %v", err)
	}

	// Second fetch should hit network again.
	if _, err := cache.GetKeys(context.Background(), srv.URL); err != nil {
		t.Fatalf("second GetKeys after invalidate: %v", err)
	}

	if fetchCount != 2 {
		t.Errorf("fetch count = %d, want 2 (invalidated)", fetchCount)
	}
}

// idpScopeKey carries the cache-partition value in the context.
type idpScopeKey struct{}

func idpScope(ctx context.Context, issuer string) string {
	v, _ := ctx.Value(idpScopeKey{}).(string)
	return v + issuer
}

// scopedCache is an injected output.Cache that partitions its entries by a
// value read from the context — the seam an out-of-tree implementation uses to
// isolate callers. It models how partitioning lives in the injected cache, not
// in idpjwks itself.
type scopedCache struct {
	mu sync.Mutex
	m  map[string]*Entry
}

func newScopedCache() *scopedCache {
	return &scopedCache{m: map[string]*Entry{}}
}

func (c *scopedCache) Load(ctx context.Context, key string) (*Entry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[idpScope(ctx, key)], nil
}

func (c *scopedCache) Store(ctx context.Context, key string, v *Entry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[idpScope(ctx, key)] = v
	return nil
}

func (c *scopedCache) Invalidate(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, idpScope(ctx, key))
	return nil
}

var _ output.Cache[*Entry] = (*scopedCache)(nil)

// With a partition-aware injected cache, the same issuer under different
// contexts is cached independently: each partition fetches once and a
// partition's entry is never served to another.
func TestCache_Scope_IsolatesSameIssuer(t *testing.T) {
	jwks, _ := testJWKS(t)
	fetchCount := 0

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetchCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	store := newMockIdPStore()
	_ = store.Save(context.Background(), idp.TrustedIDP{
		ID:       "test-idp",
		Issuer:   srv.URL,
		JWKSUri:  srv.URL + "/jwks",
		Audience: "https://authplane.example.com",
		Enabled:  true,
	})

	obs := observability.NewNoop()
	c := New(store, newScopedCache(), CacheConfig{}, obs, WithHTTPClient(srv.Client()))

	ctxA := context.WithValue(context.Background(), idpScopeKey{}, "a")
	ctxB := context.WithValue(context.Background(), idpScopeKey{}, "b")

	if _, err := c.GetKeys(ctxA, srv.URL); err != nil {
		t.Fatalf("GetKeys(A): %v", err)
	}
	if _, err := c.GetKeys(ctxB, srv.URL); err != nil {
		t.Fatalf("GetKeys(B): %v", err)
	}
	// Re-read A — served from A's partition, no new fetch.
	if _, err := c.GetKeys(ctxA, srv.URL); err != nil {
		t.Fatalf("GetKeys(A) #2: %v", err)
	}
	if fetchCount != 2 {
		t.Errorf("fetch count = %d, want 2 (one per partition)", fetchCount)
	}

	// Invalidate is partition-scoped: clearing A leaves B's entry intact.
	if err := c.InvalidateCache(ctxA, srv.URL); err != nil {
		t.Fatalf("InvalidateCache(A): %v", err)
	}
	if _, err := c.GetKeys(ctxB, srv.URL); err != nil {
		t.Fatalf("GetKeys(B) after invalidate(A): %v", err)
	}
	if fetchCount != 2 {
		t.Errorf("fetch count = %d, want 2 (B still cached)", fetchCount)
	}
}

func TestCache_UnknownIssuer(t *testing.T) {
	store := newMockIdPStore()
	obs := observability.NewNoop()
	cache := New(store, adaptercache.NewMemory[*Entry](), CacheConfig{}, obs)

	_, err := cache.GetKeys(context.Background(), "https://unknown.example.com")
	if err == nil {
		t.Fatal("expected error for unknown issuer")
	}
}

// On a fetch failure, an expired entry is served as a bounded
// stale-while-revalidate fallback while within MaxStale, then stops.
func TestCache_StaleWhileRevalidate_Bounded(t *testing.T) {
	jwks, _ := testJWKS(t)
	fail := false

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	store := newMockIdPStore()
	_ = store.Save(context.Background(), idp.TrustedIDP{
		ID:       "test-idp",
		Issuer:   srv.URL,
		JWKSUri:  srv.URL + "/jwks",
		Audience: "https://authplane.example.com",
		Enabled:  true,
	})

	obs := observability.NewNoop()
	c := New(store, adaptercache.NewMemory[*Entry](), CacheConfig{TTL: time.Hour, MaxStale: 24 * time.Hour}, obs, WithHTTPClient(srv.Client()))

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := base
	c.now = func() time.Time { return clock }

	// Warm the cache (fetch succeeds; entry expires at base+1h).
	if keys, err := c.GetKeys(context.Background(), srv.URL); err != nil || keys == nil {
		t.Fatalf("warm GetKeys = %v, %v", keys, err)
	}

	// IdP down; entry expired but within MaxStale → served stale, no error.
	fail = true
	clock = base.Add(2 * time.Hour)
	keys, err := c.GetKeys(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("SWR within maxStale returned error: %v", err)
	}
	if keys == nil || keys.Keys[0].KeyID != "test-kid" {
		t.Fatalf("SWR served %v, want stale keys", keys)
	}

	// Beyond MaxStale → stale no longer served; the fetch error surfaces.
	clock = base.Add(25 * time.Hour)
	if _, err := c.GetKeys(context.Background(), srv.URL); err == nil {
		t.Fatal("GetKeys past maxStale: expected error, got nil")
	}
}

// TestCache_GetKeys_RefusesCGNAT reproduces the scenario the 2026-08-06 audit
// executed by hand: an IdP whose jwks_uri sits in RFC 6598
// carrier-grade NAT space. The pre-fix predicate allowed it — the audit saw
// "context deadline exceeded", meaning the server had already opened a TCP
// connection and merely found nothing listening. It must be refused before any
// connect(2). The address is a literal, so this test needs no network and no DNS.
func TestCache_GetKeys_RefusesCGNAT(t *testing.T) {
	const issuer = "https://cgnat.idp.example"

	store := newMockIdPStore()
	_ = store.Save(context.Background(), idp.TrustedIDP{
		ID:       "cgnat-idp",
		Issuer:   issuer,
		JWKSUri:  "https://100.64.7.7/jwks",
		Audience: "https://authplane.example.com",
		Enabled:  true,
	})

	obs := observability.NewNoop()
	// Deliberately NOT injecting a test client: this must exercise the
	// SSRF-protected client that New builds.
	c := New(store, adaptercache.NewMemory[*Entry](), CacheConfig{FetchTimeout: 2 * time.Second}, obs)

	_, err := c.GetKeys(context.Background(), issuer)
	if err == nil {
		t.Fatal("expected SSRF refusal for CGNAT jwks_uri, got nil")
	}
	if !strings.Contains(err.Error(), "SSRF protection") {
		t.Fatalf("error = %v, want an SSRF refusal (pre-fix this was a dial timeout)", err)
	}
}

// TestSSRFSafeDialer_RejectsUnparseableHost covers the fail-open at the tail of
// the Control hook. The pre-fix condition was `ip != nil && isPrivateIP(ip)`, so
// a host that does not parse as an IP was *allowed*. Unreachable in practice --
// the dialer always supplies a literal -- but it inverts the safe default, and
// the hook is the last thing standing between a rebind and connect(2).
func TestSSRFSafeDialer_RejectsUnparseableHost(t *testing.T) {
	d := ssrfSafeDialer(2 * time.Second)

	err := d.Control("tcp", "not-an-ip:443", nil)
	if err == nil {
		t.Fatal("Control allowed an unparseable host — the guard fails open")
	}
	if !strings.Contains(err.Error(), "SSRF protection") {
		t.Errorf("error = %v, want an SSRF refusal", err)
	}
}

// TestSSRFSafeDialer_RefusesLiveLoopbackListener is the DNS-rebinding regression pin.
//
// The rebinding refutation in the audit rests entirely on the Control hook being
// installed: DialContext dials the hostname, so the validated address and the
// connected address are resolved separately. This test dials a REAL listener on
// loopback, bypassing DialContext's pre-resolution sweep entirely. If the hook
// is removed, the dial succeeds and this test fails.
func TestSSRFSafeDialer_RefusesLiveLoopbackListener(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	d := ssrfSafeDialer(2 * time.Second)
	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("dialed a live loopback listener — the Control hook is gone and the DNS-rebinding window is open")
	}
	if !strings.Contains(err.Error(), "SSRF protection") {
		t.Errorf("error = %v, want an SSRF refusal", err)
	}
}
