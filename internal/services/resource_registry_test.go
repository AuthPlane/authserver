package services

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// --- Mock output.ResourceStore ---

type mockResourceStore struct {
	resolveFn     func(slugOrURI string) ([]*resource.Resource, error)
	getByIDFn     func(id string) (*resource.Resource, error)
	listFn        func(filter output.ResourceFilter) ([]*resource.Resource, error)
	getBySlug     func(slug string) (*resource.Resource, error)
	findByRuntime func(clientID string) (*resource.Resource, error)
	createErr     error
	updateErr     error
	deleteErr     error
	createSeen    *resource.Resource
	updateSeen    *resource.Resource
	deleteSeen    string
}

var errMockNotConfigured = errors.New("mock: behavior not configured for this test")

func (m *mockResourceStore) GetByID(_ context.Context, id string) (*resource.Resource, error) {
	if m.getByIDFn == nil {
		return nil, errMockNotConfigured
	}
	return m.getByIDFn(id)
}

func (m *mockResourceStore) GetBySlug(_ context.Context, slug string) (*resource.Resource, error) {
	if m.getBySlug == nil {
		return nil, errMockNotConfigured
	}
	return m.getBySlug(slug)
}

func (m *mockResourceStore) Resolve(_ context.Context, slugOrURI string) ([]*resource.Resource, error) {
	if m.resolveFn == nil {
		return nil, errMockNotConfigured
	}
	return m.resolveFn(slugOrURI)
}

func (m *mockResourceStore) List(_ context.Context, filter output.ResourceFilter) ([]*resource.Resource, error) {
	if m.listFn == nil {
		return nil, errMockNotConfigured
	}
	return m.listFn(filter)
}

func (m *mockResourceStore) Create(_ context.Context, r *resource.Resource) error {
	m.createSeen = r
	return m.createErr
}

func (m *mockResourceStore) Update(_ context.Context, r *resource.Resource) error {
	m.updateSeen = r
	return m.updateErr
}

func (m *mockResourceStore) Delete(_ context.Context, id string) error {
	m.deleteSeen = id
	return m.deleteErr
}

func (m *mockResourceStore) FindByRuntimeClientID(_ context.Context, clientID string) (*resource.Resource, error) {
	if m.findByRuntime == nil {
		return nil, domain.ErrResourceNotFound
	}
	return m.findByRuntime(clientID)
}

// --- Mock output.BrokerProviderStore ---

type mockBrokerProviderStore struct {
	getByIDFn  func(id string) (*resource.BrokerProvider, error)
	getBySlug  func(slug string) (*resource.BrokerProvider, error)
	listFn     func() ([]*resource.BrokerProvider, error)
	createErr  error
	updateErr  error
	deleteErr  error
	createSeen *resource.BrokerProvider
	updateSeen *resource.BrokerProvider
	deleteSeen string
}

func (m *mockBrokerProviderStore) GetByID(_ context.Context, id string) (*resource.BrokerProvider, error) {
	if m.getByIDFn == nil {
		return nil, errMockNotConfigured
	}
	return m.getByIDFn(id)
}

func (m *mockBrokerProviderStore) GetBySlug(_ context.Context, slug string) (*resource.BrokerProvider, error) {
	if m.getBySlug == nil {
		return nil, errMockNotConfigured
	}
	return m.getBySlug(slug)
}

func (m *mockBrokerProviderStore) List(_ context.Context) ([]*resource.BrokerProvider, error) {
	if m.listFn == nil {
		return nil, errMockNotConfigured
	}
	return m.listFn()
}

func (m *mockBrokerProviderStore) Create(_ context.Context, p *resource.BrokerProvider) error {
	m.createSeen = p
	return m.createErr
}

func (m *mockBrokerProviderStore) Update(_ context.Context, p *resource.BrokerProvider) error {
	m.updateSeen = p
	return m.updateErr
}

func (m *mockBrokerProviderStore) Delete(_ context.Context, id string) error {
	m.deleteSeen = id
	return m.deleteErr
}

// --- Fixtures ---

func newMintResource() *resource.Resource {
	return &resource.Resource{
		ID:          "res-mint-1",
		Slug:        "my-mcp",
		DisplayName: "My MCP",
		URI:         "https://mcp.example.com",
		BackendKind: resource.BackendMint,
		Scopes: []resource.Scope{
			{Name: "read", Description: "Read access"},
			{Name: "write", Description: "Write access"},
		},
	}
}

func newBrokerResource() *resource.Resource {
	return &resource.Resource{
		ID:               "res-broker-1",
		Slug:             "github",
		DisplayName:      "GitHub",
		URI:              "https://api.github.com",
		BackendKind:      resource.BackendBroker,
		BrokerProviderID: "bp-github",
		Scopes: []resource.Scope{
			{Name: "repo", Description: "Repo access", Upstream: "repo"},
		},
	}
}

func newGitHubProvider() *resource.BrokerProvider {
	return &resource.BrokerProvider{
		ID:          "bp-github",
		Slug:        "github",
		DisplayName: "GitHub",
		Protocol:    resource.ProtocolOAuth,
	}
}

func newRegistry(rs *mockResourceStore, bps *mockBrokerProviderStore) *ResourceRegistry {
	return NewResourceRegistry(rs, bps, observability.NewNoop())
}

// --- Resolve tests ---

func TestResourceRegistry_Resolve_BySlug_Single(t *testing.T) {
	want := newMintResource()
	rs := &mockResourceStore{
		resolveFn: func(slugOrURI string) ([]*resource.Resource, error) {
			if slugOrURI != "my-mcp" {
				t.Fatalf("Resolve called with %q, want %q", slugOrURI, "my-mcp")
			}
			return []*resource.Resource{want}, nil
		},
	}
	reg := newRegistry(rs, &mockBrokerProviderStore{})

	got, err := reg.Resolve(context.Background(), "my-mcp")
	if err != nil {
		t.Fatalf("Resolve: unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("Resolve returned %+v, want %+v", got, want)
	}
}

func TestResourceRegistry_Resolve_NotFound(t *testing.T) {
	rs := &mockResourceStore{
		resolveFn: func(_ string) ([]*resource.Resource, error) {
			return []*resource.Resource{}, nil
		},
	}
	reg := newRegistry(rs, &mockBrokerProviderStore{})

	got, err := reg.Resolve(context.Background(), "missing")
	if !errors.Is(err, domain.ErrResourceNotFound) {
		t.Fatalf("Resolve error = %v, want %v", err, domain.ErrResourceNotFound)
	}
	if got != nil {
		t.Errorf("Resolve returned %+v, want nil", got)
	}
}

func TestResourceRegistry_Resolve_Ambiguous(t *testing.T) {
	a := newMintResource()
	b := newBrokerResource()
	rs := &mockResourceStore{
		resolveFn: func(_ string) ([]*resource.Resource, error) {
			return []*resource.Resource{a, b}, nil
		},
	}
	reg := newRegistry(rs, &mockBrokerProviderStore{})

	got, err := reg.Resolve(context.Background(), "https://mcp.example.com")
	if !errors.Is(err, domain.ErrAmbiguousResource) {
		t.Fatalf("Resolve error = %v, want %v", err, domain.ErrAmbiguousResource)
	}
	if got != nil {
		t.Errorf("Resolve returned %+v, want nil", got)
	}
}

// --- GetWithProvider tests ---

func TestResourceRegistry_GetWithProvider_BrokerKind_LoadsProvider(t *testing.T) {
	res := newBrokerResource()
	prov := newGitHubProvider()

	rs := &mockResourceStore{
		getByIDFn: func(id string) (*resource.Resource, error) {
			if id != res.ID {
				t.Fatalf("GetByID called with %q, want %q", id, res.ID)
			}
			return res, nil
		},
	}
	bps := &mockBrokerProviderStore{
		getByIDFn: func(id string) (*resource.BrokerProvider, error) {
			if id != res.BrokerProviderID {
				t.Fatalf("provider GetByID called with %q, want %q", id, res.BrokerProviderID)
			}
			return prov, nil
		},
	}
	reg := newRegistry(rs, bps)

	gotRes, gotProv, err := reg.GetWithProvider(context.Background(), res.ID)
	if err != nil {
		t.Fatalf("GetWithProvider: unexpected error: %v", err)
	}
	if gotRes != res {
		t.Errorf("resource = %+v, want %+v", gotRes, res)
	}
	if gotProv != prov {
		t.Errorf("provider = %+v, want %+v", gotProv, prov)
	}
}

func TestResourceRegistry_GetWithProvider_MintKind_NoProvider(t *testing.T) {
	res := newMintResource()

	rs := &mockResourceStore{
		getByIDFn: func(id string) (*resource.Resource, error) {
			if id != res.ID {
				t.Fatalf("GetByID called with %q, want %q", id, res.ID)
			}
			return res, nil
		},
	}
	// BrokerProviderStore must NOT be called for mint resources.
	bps := &mockBrokerProviderStore{
		getByIDFn: func(id string) (*resource.BrokerProvider, error) {
			t.Fatalf("BrokerProviderStore.GetByID should not be called for mint resource (got id=%q)", id)
			return nil, nil
		},
	}
	reg := newRegistry(rs, bps)

	gotRes, gotProv, err := reg.GetWithProvider(context.Background(), res.ID)
	if err != nil {
		t.Fatalf("GetWithProvider: unexpected error: %v", err)
	}
	if gotRes != res {
		t.Errorf("resource = %+v, want %+v", gotRes, res)
	}
	if gotProv != nil {
		t.Errorf("provider = %+v, want nil", gotProv)
	}
}

func TestResourceRegistry_GetWithProvider_BrokerKind_ProviderMissing_Error(t *testing.T) {
	res := newBrokerResource()

	rs := &mockResourceStore{
		getByIDFn: func(id string) (*resource.Resource, error) {
			if id != res.ID {
				t.Fatalf("GetByID called with %q, want %q", id, res.ID)
			}
			return res, nil
		},
	}
	bps := &mockBrokerProviderStore{
		getByIDFn: func(_ string) (*resource.BrokerProvider, error) {
			return nil, domain.ErrResourceNotFound
		},
	}
	reg := newRegistry(rs, bps)

	gotRes, gotProv, err := reg.GetWithProvider(context.Background(), res.ID)
	if err == nil {
		t.Fatal("GetWithProvider: expected error for missing provider")
	}
	// The wrap must preserve domain.ErrResourceNotFound for callers who care.
	if !errors.Is(err, domain.ErrResourceNotFound) {
		t.Errorf("error chain does not carry ErrResourceNotFound: %v", err)
	}
	// And the wrapped error message must mention the broken FK so logs are useful.
	if msg := err.Error(); !strings.Contains(msg, res.BrokerProviderID) || !strings.Contains(msg, res.ID) {
		t.Errorf("error message %q should reference both resource_id and broker_provider_id", msg)
	}
	if gotRes != nil || gotProv != nil {
		t.Errorf("on error want (nil, nil), got (%+v, %+v)", gotRes, gotProv)
	}
}

// --- ListScopes tests ---

func TestResourceRegistry_ListScopes_ReturnsResourceScopes(t *testing.T) {
	res := newMintResource()

	rs := &mockResourceStore{
		getByIDFn: func(id string) (*resource.Resource, error) {
			if id != res.ID {
				t.Fatalf("GetByID called with %q, want %q", id, res.ID)
			}
			return res, nil
		},
	}
	reg := newRegistry(rs, &mockBrokerProviderStore{})

	got, err := reg.ListScopes(context.Background(), res.ID)
	if err != nil {
		t.Fatalf("ListScopes: unexpected error: %v", err)
	}
	if len(got) != len(res.Scopes) {
		t.Fatalf("ListScopes returned %d scopes, want %d", len(got), len(res.Scopes))
	}
	for i, sc := range got {
		if sc.Name != res.Scopes[i].Name || sc.Description != res.Scopes[i].Description {
			t.Errorf("scope[%d] = %+v, want %+v", i, sc, res.Scopes[i])
		}
	}
}

func TestResourceRegistry_ListScopes_NotFound(t *testing.T) {
	rs := &mockResourceStore{
		getByIDFn: func(_ string) (*resource.Resource, error) {
			return nil, domain.ErrResourceNotFound
		},
	}
	reg := newRegistry(rs, &mockBrokerProviderStore{})

	got, err := reg.ListScopes(context.Background(), "res-does-not-exist")
	if !errors.Is(err, domain.ErrResourceNotFound) {
		t.Fatalf("ListScopes error = %v, want %v", err, domain.ErrResourceNotFound)
	}
	if got != nil {
		t.Errorf("ListScopes returned %+v, want nil", got)
	}
}

// --- List (backward-compat) tests ---

func TestResourceRegistry_List_ReturnsResourceInfo(t *testing.T) {
	res := newMintResource()

	rs := &mockResourceStore{
		listFn: func(filter output.ResourceFilter) ([]*resource.Resource, error) {
			if filter != (output.ResourceFilter{}) {
				t.Errorf("List called with non-empty filter %+v, want empty", filter)
			}
			return []*resource.Resource{res}, nil
		},
	}
	reg := newRegistry(rs, &mockBrokerProviderStore{})

	infos := reg.List()
	if len(infos) != 1 {
		t.Fatalf("List returned %d infos, want 1", len(infos))
	}
	got := infos[0]
	if got.URI != res.URI {
		t.Errorf("URI = %q, want %q", got.URI, res.URI)
	}
	if len(got.Scopes) != 2 || got.Scopes[0] != "read" || got.Scopes[1] != "write" {
		t.Errorf("Scopes = %v, want [read write]", got.Scopes)
	}
	if got.ScopeDescriptions["read"] != "Read access" || got.ScopeDescriptions["write"] != "Write access" {
		t.Errorf("ScopeDescriptions = %v, want read/write descriptions populated", got.ScopeDescriptions)
	}
	// ClientID stays empty until a follow-up wires it to read
	// Policy.Exchange.AllowedClientIDs.
	if got.ClientID != "" {
		t.Errorf("ClientID = %q, want \"\" (v4 has no may_act seam on Resource)", got.ClientID)
	}
}

func TestResourceRegistry_List_BackendKindFilteredCorrectly(t *testing.T) {
	mint := newMintResource()
	broker := newBrokerResource()

	rs := &mockResourceStore{
		listFn: func(_ output.ResourceFilter) ([]*resource.Resource, error) {
			return []*resource.Resource{mint, broker}, nil
		},
	}
	reg := newRegistry(rs, &mockBrokerProviderStore{})

	infos := reg.List()
	if len(infos) != 2 {
		t.Fatalf("List returned %d infos, want 2 (one mint + one broker)", len(infos))
	}

	uris := map[string]bool{infos[0].URI: true, infos[1].URI: true}
	if !uris[mint.URI] {
		t.Errorf("mint URI %q missing from List result %v", mint.URI, uris)
	}
	if !uris[broker.URI] {
		t.Errorf("broker URI %q missing from List result %v — consumers like authorize need both kinds", broker.URI, uris)
	}
}
