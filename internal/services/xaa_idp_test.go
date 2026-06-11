package services

import (
	"context"
	"fmt"
	"testing"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/idp"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"

	"github.com/go-jose/go-jose/v4"
)

// --- Mock IdP Store ---

type mockIDPStore struct {
	idps map[string]*idp.TrustedIDP
}

func newMockIdPStore() *mockIDPStore {
	return &mockIDPStore{idps: make(map[string]*idp.TrustedIDP)}
}

func (m *mockIDPStore) Save(_ context.Context, i idp.TrustedIDP) error {
	m.idps[i.ID] = &i
	return nil
}

func (m *mockIDPStore) GetByID(_ context.Context, id string) (*idp.TrustedIDP, error) {
	i, ok := m.idps[id]
	if !ok {
		return nil, domain.ErrIDPNotFound
	}
	return i, nil
}

func (m *mockIDPStore) GetByIssuer(_ context.Context, issuer string) (*idp.TrustedIDP, error) {
	for _, i := range m.idps {
		if i.Issuer == issuer {
			return i, nil
		}
	}
	return nil, domain.ErrIDPNotFound
}

func (m *mockIDPStore) List(_ context.Context) ([]idp.TrustedIDP, error) {
	var result []idp.TrustedIDP
	for _, i := range m.idps {
		result = append(result, *i)
	}
	return result, nil
}

func (m *mockIDPStore) Delete(_ context.Context, id string) error {
	if _, ok := m.idps[id]; !ok {
		return domain.ErrIDPNotFound
	}
	delete(m.idps, id)
	return nil
}

var _ output.IDPStore = (*mockIDPStore)(nil)

// --- Mock JWKS Cache ---

type mockJWKSCache struct {
	invalidated map[string]bool
}

func newMockJWKSCache() *mockJWKSCache {
	return &mockJWKSCache{invalidated: make(map[string]bool)}
}

func (m *mockJWKSCache) GetKeys(_ context.Context, _ string) (*jose.JSONWebKeySet, error) {
	return &jose.JSONWebKeySet{}, nil
}

func (m *mockJWKSCache) InvalidateCache(_ context.Context, issuer string) error {
	m.invalidated[issuer] = true
	return nil
}

var _ output.IDPJWKSCache = (*mockJWKSCache)(nil)

// --- Mock Audit Recorder ---

type xaaMockAudit struct{}

func (m *xaaMockAudit) Record(_ context.Context, _ audit.Event) {}

// --- Discovery mock ---

func mockDiscover(_ context.Context, issuerURL string) (string, error) {
	return issuerURL + "/.well-known/jwks.json", nil
}

func mockDiscoverFail(_ context.Context, _ string) (string, error) {
	return "", fmt.Errorf("discovery failed")
}

func newTestXAAIDPService(store *mockIDPStore, cache *mockJWKSCache, discover JWKSDiscoveryFunc) *XAAIDPService {
	obs := observability.NewNoop()
	return NewXAAIDPService(store, cache, discover, "https://authplane.example.com", obs, &xaaMockAudit{})
}

func TestXAAIDPService_RegisterIDP(t *testing.T) {
	store := newMockIdPStore()
	cache := newMockJWKSCache()
	svc := newTestXAAIDPService(store, cache, mockDiscover)

	entity, err := svc.RegisterIDP(context.Background(), input.RegisterIDPRequest{
		Name:   "Acme Okta",
		Issuer: "https://acme.okta.com",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if entity.Name != "Acme Okta" {
		t.Errorf("name = %q, want %q", entity.Name, "Acme Okta")
	}
	if entity.Issuer != "https://acme.okta.com" {
		t.Errorf("issuer = %q", entity.Issuer)
	}
	if entity.Audience != "https://authplane.example.com" {
		t.Errorf("audience = %q, want default issuer", entity.Audience)
	}
	if entity.JWKSUri != "https://acme.okta.com/.well-known/jwks.json" {
		t.Errorf("jwks_uri = %q, expected discovered value", entity.JWKSUri)
	}
	if !entity.Enabled {
		t.Error("expected enabled = true")
	}
}

func TestXAAIDPService_RegisterIdP_WithExplicitJWKSUri(t *testing.T) {
	store := newMockIdPStore()
	cache := newMockJWKSCache()
	svc := newTestXAAIDPService(store, cache, mockDiscover)

	entity, err := svc.RegisterIDP(context.Background(), input.RegisterIDPRequest{
		Name:    "Acme Okta",
		Issuer:  "https://acme.okta.com",
		JWKSUri: "https://acme.okta.com/custom/jwks",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if entity.JWKSUri != "https://acme.okta.com/custom/jwks" {
		t.Errorf("jwks_uri = %q, want explicit value", entity.JWKSUri)
	}
}

func TestXAAIDPService_RegisterIdP_DiscoveryFails(t *testing.T) {
	store := newMockIdPStore()
	cache := newMockJWKSCache()
	svc := newTestXAAIDPService(store, cache, mockDiscoverFail)

	_, err := svc.RegisterIDP(context.Background(), input.RegisterIDPRequest{
		Name:   "Acme Okta",
		Issuer: "https://acme.okta.com",
	})
	if err == nil {
		t.Fatal("expected error when discovery fails")
	}
}

func TestXAAIDPService_RegisterIdP_ValidationFails(t *testing.T) {
	store := newMockIdPStore()
	cache := newMockJWKSCache()
	svc := newTestXAAIDPService(store, cache, mockDiscover)

	_, err := svc.RegisterIDP(context.Background(), input.RegisterIDPRequest{
		Name:   "Bad IdP",
		Issuer: "http://insecure.example.com",
	})
	if err == nil {
		t.Fatal("expected validation error for HTTP issuer")
	}
}

func TestXAAIDPService_UpdateIDP(t *testing.T) {
	store := newMockIdPStore()
	cache := newMockJWKSCache()
	svc := newTestXAAIDPService(store, cache, mockDiscover)

	entity, err := svc.RegisterIDP(context.Background(), input.RegisterIDPRequest{
		Name:   "Acme Okta",
		Issuer: "https://acme.okta.com",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	newName := "Updated Okta"
	disabled := false
	updated, err := svc.UpdateIDP(context.Background(), entity.ID, input.UpdateIDPRequest{
		Name:    &newName,
		Enabled: &disabled,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	if updated.Name != "Updated Okta" {
		t.Errorf("name = %q, want %q", updated.Name, "Updated Okta")
	}
	if updated.Enabled != false {
		t.Error("expected enabled = false")
	}
}

func TestXAAIDPService_DeleteIDP(t *testing.T) {
	store := newMockIdPStore()
	cache := newMockJWKSCache()
	svc := newTestXAAIDPService(store, cache, mockDiscover)

	entity, err := svc.RegisterIDP(context.Background(), input.RegisterIDPRequest{
		Name:   "Acme Okta",
		Issuer: "https://acme.okta.com",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if delErr := svc.DeleteIDP(context.Background(), entity.ID); delErr != nil {
		t.Fatalf("delete: %v", delErr)
	}

	if !cache.invalidated["https://acme.okta.com"] {
		t.Error("expected cache invalidation for deleted IdP's issuer")
	}

	_, err = svc.GetIDP(context.Background(), entity.ID)
	if err != domain.ErrIDPNotFound {
		t.Errorf("expected ErrIDPNotFound after delete, got: %v", err)
	}
}

func TestXAAIDPService_DeleteIdP_NotFound(t *testing.T) {
	store := newMockIdPStore()
	cache := newMockJWKSCache()
	svc := newTestXAAIDPService(store, cache, mockDiscover)

	err := svc.DeleteIDP(context.Background(), "nonexistent")
	if err != domain.ErrIDPNotFound {
		t.Errorf("expected ErrIDPNotFound, got: %v", err)
	}
}

func TestXAAIDPService_ListIDPs(t *testing.T) {
	store := newMockIdPStore()
	cache := newMockJWKSCache()
	svc := newTestXAAIDPService(store, cache, mockDiscover)

	if _, err := svc.RegisterIDP(context.Background(), input.RegisterIDPRequest{
		Name:   "IdP A",
		Issuer: "https://a.example.com",
	}); err != nil {
		t.Fatalf("register a: %v", err)
	}

	if _, err := svc.RegisterIDP(context.Background(), input.RegisterIDPRequest{
		Name:   "IdP B",
		Issuer: "https://b.example.com",
	}); err != nil {
		t.Fatalf("register b: %v", err)
	}

	list, err := svc.ListIDPs(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("len = %d, want 2", len(list))
	}
}
