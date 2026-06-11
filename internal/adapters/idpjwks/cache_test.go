package idpjwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

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
	cache := &Cache{
		entries:  make(map[string]*cacheEntry),
		idpStore: store,
		client:   srv.Client(),
		ttl:      1 * time.Hour,
		logger:   obs.Logger,
		tracer:   obs.Tracer,
	}

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
	cache := &Cache{
		entries:  make(map[string]*cacheEntry),
		idpStore: store,
		client:   srv.Client(),
		ttl:      1 * time.Hour,
		logger:   obs.Logger,
		tracer:   obs.Tracer,
	}

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
	cache := &Cache{
		entries:  make(map[string]*cacheEntry),
		idpStore: store,
		client:   srv.Client(),
		ttl:      1 * time.Hour,
		logger:   obs.Logger,
		tracer:   obs.Tracer,
	}

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

func TestCache_UnknownIssuer(t *testing.T) {
	store := newMockIdPStore()
	obs := observability.NewNoop()
	cache := &Cache{
		entries:  make(map[string]*cacheEntry),
		idpStore: store,
		client:   http.DefaultClient,
		ttl:      1 * time.Hour,
		logger:   obs.Logger,
		tracer:   obs.Tracer,
	}

	_, err := cache.GetKeys(context.Background(), "https://unknown.example.com")
	if err == nil {
		t.Fatal("expected error for unknown issuer")
	}
}
