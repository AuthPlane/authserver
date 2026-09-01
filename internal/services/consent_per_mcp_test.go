//go:build integration

package services_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/adapters/sqlite"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/domain/session"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

// newTestRegistry builds a ResourceRegistry over the sqlite test stores.
// 's ConsentService and AuthorizeService consume *ResourceRegistry
// directly; the test seam is a real registry over an in-memory DB.
func newTestRegistry(stores *sqlite.Stores) *services.ResourceRegistry {
	return services.NewResourceRegistry(stores.Resource, stores.BrokerProvider, testObs())
}

// seedMintResource inserts a Mint Resource into the test DB. Returns the
// created row so callers can assert on its ID. The slug must be lowercase
// and ≤ 64 chars (the data model).
func seedMintResource(t *testing.T, stores *sqlite.Stores, slug, displayName, uri string, scopes ...resource.Scope) *resource.Resource {
	t.Helper()
	now := time.Now().UTC()
	r := &resource.Resource{
		ID:          crypto.GenerateRandomString(16),
		Slug:        slug,
		DisplayName: displayName,
		URI:         uri,
		BackendKind: resource.BackendMint,
		Scopes:      scopes,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := stores.Resource.Create(context.Background(), r); err != nil {
		t.Fatalf("seed mint resource %q: %v", slug, err)
	}
	return r
}

// seedBrokerResource inserts a Broker-backed Resource. A BrokerProvider row
// is created first to satisfy the FK + CHECK constraint on resources.
func seedBrokerResource(t *testing.T, stores *sqlite.Stores, slug, displayName, uri string, scopes ...resource.Scope) *resource.Resource {
	t.Helper()
	now := time.Now().UTC()
	bp := &resource.BrokerProvider{
		ID:          crypto.GenerateRandomString(16),
		Slug:        slug + "-provider",
		DisplayName: displayName + " Provider",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"client_id":"stub","client_secret_ref":"STUB"}`),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := stores.BrokerProvider.Create(context.Background(), bp); err != nil {
		t.Fatalf("seed broker provider: %v", err)
	}
	r := &resource.Resource{
		ID:               crypto.GenerateRandomString(16),
		Slug:             slug,
		DisplayName:      displayName,
		URI:              uri,
		BackendKind:      resource.BackendBroker,
		BrokerProviderID: bp.ID,
		Scopes:           scopes,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := stores.Resource.Create(context.Background(), r); err != nil {
		t.Fatalf("seed broker resource %q: %v", slug, err)
	}
	return r
}

// seedConsentTestSession creates a client + session pinned to the given
// resource URI / scope string so the rewritten ConsentService can resolve
// it through the registry.
func seedConsentTestSession(t *testing.T, stores *sqlite.Stores, scopeStr, resourceURI, userID string) (*client.Client, *session.AuthSession) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "Per-MCP Consent Client",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceDCR,
		IssuedAt:                now,
		UpdatedAt:               now,
	}
	if err := stores.Client.Create(ctx, c); err != nil {
		t.Fatalf("create client: %v", err)
	}
	if err := seedUser(ctx, stores, userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	verifier := crypto.GenerateVerifier()
	sess := &session.AuthSession{
		ID:                  crypto.GenerateRandomString(16),
		ClientID:            c.ID,
		UserID:              userID,
		RedirectURI:         "https://app.example.com/callback",
		Scope:               scopeStr,
		Resource:            resourceURI,
		State:               "state-per-mcp",
		CodeHash:            crypto.HashSHA256(crypto.GenerateAuthCode()),
		CodeChallenge:       crypto.ComputeS256Challenge(verifier),
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(session.AuthCodeTTL),
		CreatedAt:           now,
	}
	if err := stores.Session.Create(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	return c, sess
}

// ---  — per-MCP consent screen + unified store tests ---

func TestConsentService_GetPending_PerMCPScopes_Mint_HappyPath(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	registry := newTestRegistry(stores)

	const uri = "https://test-mcp.example.com"
	seedMintResource(t, stores, "test-mcp", "Test MCP", uri,
		resource.Scope{Name: "tasks:summarize", Description: "Summarize your tasks"},
		resource.Scope{Name: "tasks:list", Description: "List your tasks"},
	)

	consentSvc := services.NewConsentService(
		stores.ConsentGrant, stores.Session, stores.Client, registry, obs, nil,
	)
	_, sess := seedConsentTestSession(t, stores, "tasks:summarize tasks:list", uri, "user-happy")

	view, err := consentSvc.GetPendingConsent(context.Background(), sess.ID)
	if err != nil {
		t.Fatalf("GetPendingConsent: %v", err)
	}
	if view.ResourceDisplayName != "Test MCP" {
		t.Errorf("ResourceDisplayName: got %q, want %q", view.ResourceDisplayName, "Test MCP")
	}
	if view.ResourceSlug != "test-mcp" {
		t.Errorf("ResourceSlug: got %q, want %q", view.ResourceSlug, "test-mcp")
	}
	if view.Resource != uri {
		t.Errorf("Resource: got %q, want %q (canonical URI)", view.Resource, uri)
	}
	if len(view.Scopes) != 2 {
		t.Fatalf("expected 2 scopes, got %d", len(view.Scopes))
	}
	if view.Scopes[0].Description != "Summarize your tasks" || view.Scopes[1].Description != "List your tasks" {
		t.Errorf("scope descriptions wrong: %+v", view.Scopes)
	}
}

func TestConsentService_GetPending_ResolvesBySlug(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	registry := newTestRegistry(stores)

	const uri = "https://slug-mcp.example.com"
	seedMintResource(t, stores, "slug-mcp", "Slug MCP", uri,
		resource.Scope{Name: "ping", Description: "Ping"},
	)

	consentSvc := services.NewConsentService(
		stores.ConsentGrant, stores.Session, stores.Client, registry, obs, nil,
	)
	// Session carries the slug, not the URI.
	_, sess := seedConsentTestSession(t, stores, "ping", "slug-mcp", "user-slug")

	view, err := consentSvc.GetPendingConsent(context.Background(), sess.ID)
	if err != nil {
		t.Fatalf("GetPendingConsent: %v", err)
	}
	if view.Resource != uri {
		t.Errorf("Resource: got %q, want canonical URI %q", view.Resource, uri)
	}
	if view.ResourceSlug != "slug-mcp" {
		t.Errorf("ResourceSlug: got %q, want %q", view.ResourceSlug, "slug-mcp")
	}
}

func TestConsentService_GetPending_RejectsBrokerResource(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	registry := newTestRegistry(stores)

	const uri = "https://broker-resource.example.com"
	seedBrokerResource(t, stores, "broker-resource", "Broker Resource", uri,
		resource.Scope{Name: "read", Description: "Read"},
	)

	consentSvc := services.NewConsentService(
		stores.ConsentGrant, stores.Session, stores.Client, registry, obs, nil,
	)
	_, sess := seedConsentTestSession(t, stores, "read", uri, "user-broker")

	_, err := consentSvc.GetPendingConsent(context.Background(), sess.ID)
	if !errors.Is(err, domain.ErrConsentResourceNotMint) {
		t.Fatalf("expected ErrConsentResourceNotMint, got: %v", err)
	}
}

func TestConsentService_GetPending_ResourceNotFound(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	registry := newTestRegistry(stores)

	consentSvc := services.NewConsentService(
		stores.ConsentGrant, stores.Session, stores.Client, registry, obs, nil,
	)
	_, sess := seedConsentTestSession(t, stores, "ping", "no-such-resource", "user-missing")

	_, err := consentSvc.GetPendingConsent(context.Background(), sess.ID)
	if !errors.Is(err, domain.ErrResourceNotFound) {
		t.Fatalf("expected ErrResourceNotFound, got: %v", err)
	}
}

func TestConsentService_GetPending_OmitsScopesNotInRequestedSet(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	registry := newTestRegistry(stores)

	const uri = "https://catalog-mcp.example.com"
	seedMintResource(t, stores, "catalog-mcp", "Catalog", uri,
		resource.Scope{Name: "a", Description: "A scope"},
		resource.Scope{Name: "b", Description: "B scope"},
		resource.Scope{Name: "c", Description: "C scope"},
	)

	consentSvc := services.NewConsentService(
		stores.ConsentGrant, stores.Session, stores.Client, registry, obs, nil,
	)
	_, sess := seedConsentTestSession(t, stores, "a c", uri, "user-omit")

	view, err := consentSvc.GetPendingConsent(context.Background(), sess.ID)
	if err != nil {
		t.Fatalf("GetPendingConsent: %v", err)
	}
	if len(view.Scopes) != 2 {
		t.Fatalf("expected 2 scopes, got %d: %+v", len(view.Scopes), view.Scopes)
	}
	if view.Scopes[0].Name != "a" || view.Scopes[1].Name != "c" {
		t.Errorf("expected [a c] in catalog order, got %+v", view.Scopes)
	}
}

func TestConsentService_GetPending_PreservesCatalogOrder(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	registry := newTestRegistry(stores)

	const uri = "https://order-mcp.example.com"
	seedMintResource(t, stores, "order-mcp", "Order", uri,
		resource.Scope{Name: "alpha", Description: "Alpha"},
		resource.Scope{Name: "beta", Description: "Beta"},
		resource.Scope{Name: "gamma", Description: "Gamma"},
	)

	consentSvc := services.NewConsentService(
		stores.ConsentGrant, stores.Session, stores.Client, registry, obs, nil,
	)
	// Request scopes in reverse order — view should still follow catalog order.
	_, sess := seedConsentTestSession(t, stores, "gamma alpha beta", uri, "user-order")

	view, err := consentSvc.GetPendingConsent(context.Background(), sess.ID)
	if err != nil {
		t.Fatalf("GetPendingConsent: %v", err)
	}
	if len(view.Scopes) != 3 {
		t.Fatalf("expected 3 scopes, got %d", len(view.Scopes))
	}
	want := []string{"alpha", "beta", "gamma"}
	for i, s := range view.Scopes {
		if s.Name != want[i] {
			t.Errorf("scope[%d]: got %q, want %q (catalog order)", i, s.Name, want[i])
		}
	}
}

func TestConsentService_GrantConsent_WritesToUnifiedStore(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	registry := newTestRegistry(stores)

	const uri = "https://grant-mcp.example.com"
	res := seedMintResource(t, stores, "grant-mcp", "Grant", uri,
		resource.Scope{Name: "tasks:summarize", Description: "Summarize"},
		resource.Scope{Name: "tasks:list", Description: "List"},
	)

	consentSvc := services.NewConsentService(
		stores.ConsentGrant, stores.Session, stores.Client, registry, obs, nil,
	)
	c, sess := seedConsentTestSession(t, stores, "tasks:summarize tasks:list", uri, "user-grant")

	_, err := consentSvc.GrantConsent(context.Background(), input.GrantConsentRequest{
		SessionID:      sess.ID,
		UserID:         "user-grant",
		ApprovedScopes: []string{"tasks:summarize", "tasks:list"},
	})
	if err != nil {
		t.Fatalf("GrantConsent: %v", err)
	}

	got, err := stores.ConsentGrant.Get(context.Background(), "user-grant", c.ID, res.ID)
	if err != nil {
		t.Fatalf("get unified grant: %v", err)
	}
	if got == nil {
		t.Fatal("expected unified consent grant row, got nil — write side did not land in renamed table")
	}
	if got.ResourceID != res.ID {
		t.Errorf("ResourceID: got %q, want %q (resource UUID, NOT URI)", got.ResourceID, res.ID)
	}
	if len(got.Scopes) != 2 {
		t.Errorf("Scopes len: got %d, want 2", len(got.Scopes))
	}
	for _, s := range got.Scopes {
		if strings.Contains(s, " ") {
			t.Errorf("scope %q contains space — must be discrete slice elements, not a space-joined string", s)
		}
	}
}

func TestConsentService_GrantConsent_ScopesNarrowedToApproved(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	registry := newTestRegistry(stores)

	const uri = "https://narrow-mcp.example.com"
	res := seedMintResource(t, stores, "narrow-mcp", "Narrow", uri,
		resource.Scope{Name: "a", Description: "A"},
		resource.Scope{Name: "b", Description: "B"},
		resource.Scope{Name: "c", Description: "C"},
	)
	consentSvc := services.NewConsentService(
		stores.ConsentGrant, stores.Session, stores.Client, registry, obs, nil,
	)
	c, sess := seedConsentTestSession(t, stores, "a b c", uri, "user-narrow")

	_, err := consentSvc.GrantConsent(context.Background(), input.GrantConsentRequest{
		SessionID:      sess.ID,
		UserID:         "user-narrow",
		ApprovedScopes: []string{"a", "c"},
	})
	if err != nil {
		t.Fatalf("GrantConsent: %v", err)
	}

	got, err := stores.ConsentGrant.Get(context.Background(), "user-narrow", c.ID, res.ID)
	if err != nil || got == nil {
		t.Fatalf("get unified grant: %v / nil=%v", err, got == nil)
	}
	if len(got.Scopes) != 2 {
		t.Fatalf("expected 2 scopes (narrowed), got %d: %v", len(got.Scopes), got.Scopes)
	}
}

// Regression for the consent zero-scope audit finding: a form submitted
// with action=allow but no scopes checked must NOT be interpreted as
// "approve all requested scopes." The service rejects with invalid_scope
// so the handler can show the user a "select at least one" page.
func TestConsentService_GrantConsent_RejectsEmptyApprovedScopes(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	registry := newTestRegistry(stores)

	const uri = "https://empty-mcp.example.com"
	res := seedMintResource(t, stores, "empty-mcp", "Empty", uri,
		resource.Scope{Name: "read", Description: "Read"},
		resource.Scope{Name: "write", Description: "Write"},
	)
	consentSvc := services.NewConsentService(
		stores.ConsentGrant, stores.Session, stores.Client, registry, obs, nil,
	)
	_, sess := seedConsentTestSession(t, stores, "read write", uri, "user-empty")

	_, err := consentSvc.GrantConsent(context.Background(), input.GrantConsentRequest{
		SessionID:      sess.ID,
		UserID:         "user-empty",
		ApprovedScopes: nil, // user unchecked everything
	})
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Fatalf("expected ErrInvalidScope, got: %v", err)
	}
	// And no consent grant was written — empty approval must not become a
	// silent "approve everything."
	got, err := stores.ConsentGrant.Get(context.Background(), "user-empty", sess.ClientID, res.ID)
	if err != nil {
		t.Fatalf("get grant: %v", err)
	}
	if got != nil {
		t.Errorf("empty approval must not persist a grant, got: %+v", got)
	}
}

func TestConsentService_GrantConsent_RejectsApprovedScopesExceedingRequested(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	registry := newTestRegistry(stores)

	const uri = "https://escalate-mcp.example.com"
	seedMintResource(t, stores, "escalate-mcp", "Escalate", uri,
		resource.Scope{Name: "read", Description: "Read"},
		resource.Scope{Name: "admin", Description: "Admin"},
	)
	consentSvc := services.NewConsentService(
		stores.ConsentGrant, stores.Session, stores.Client, registry, obs, nil,
	)
	_, sess := seedConsentTestSession(t, stores, "read", uri, "user-escalate")

	_, err := consentSvc.GrantConsent(context.Background(), input.GrantConsentRequest{
		SessionID:      sess.ID,
		UserID:         "user-escalate",
		ApprovedScopes: []string{"read", "admin"}, // admin not requested
	})
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Fatalf("expected ErrInvalidScope, got: %v", err)
	}
}

func TestConsentService_GrantConsent_RememberFlagIsNoOp_StillPersists(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	registry := newTestRegistry(stores)

	const uri = "https://remember-mcp.example.com"
	res := seedMintResource(t, stores, "remember-mcp", "Remember", uri,
		resource.Scope{Name: "ping", Description: "Ping"},
	)
	consentSvc := services.NewConsentService(
		stores.ConsentGrant, stores.Session, stores.Client, registry, obs, nil,
	)
	c, sess := seedConsentTestSession(t, stores, "ping", uri, "user-remember")

	// Submit with Remember=false — unified store always writes ( §187).
	_, err := consentSvc.GrantConsent(context.Background(), input.GrantConsentRequest{
		SessionID:      sess.ID,
		UserID:         "user-remember",
		ApprovedScopes: []string{"ping"},
		Remember:       false,
	})
	if err != nil {
		t.Fatalf("GrantConsent: %v", err)
	}
	got, err := stores.ConsentGrant.Get(context.Background(), "user-remember", c.ID, res.ID)
	if err != nil {
		t.Fatalf("get unified grant: %v", err)
	}
	if got == nil {
		t.Fatal("Remember=false must still persist (unified store is unconditional)")
	}
}

func TestConsentService_DenyConsent_NoConsentGrantWritten_SessionDeleted(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	registry := newTestRegistry(stores)

	const uri = "https://deny-mcp.example.com"
	res := seedMintResource(t, stores, "deny-mcp", "Deny", uri,
		resource.Scope{Name: "ping", Description: "Ping"},
	)
	consentSvc := services.NewConsentService(
		stores.ConsentGrant, stores.Session, stores.Client, registry, obs, nil,
	)
	_, sess := seedConsentTestSession(t, stores, "ping", uri, "user-deny")

	if err := consentSvc.DenyConsent(context.Background(), sess.ID, "user-deny"); !errors.Is(err, domain.ErrConsentRequired) {
		t.Fatalf("expected ErrConsentRequired, got: %v", err)
	}

	// No consent grant — deny must not become a silent approval.
	got, err := stores.ConsentGrant.Get(context.Background(), "user-deny", sess.ClientID, res.ID)
	if err != nil {
		t.Fatalf("get unified grant: %v", err)
	}
	if got != nil {
		t.Error("deny path must not write to unified store")
	}

	// Session deleted — the user cannot revisit the same consent URL and
	// click Allow inside the TTL. This is the load-bearing behavior of
	// the deny path; without it, denial is non-final.
	if _, err := stores.Session.GetByID(context.Background(), sess.ID); !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("expected ErrInvalidGrant for deleted session, got: %v", err)
	}
}
