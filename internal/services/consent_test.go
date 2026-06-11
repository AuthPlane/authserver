//go:build integration

package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/adapters/sqlite"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/domain/session"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

// Matrix: 15.7 — upgraded from ⚠️: consent.granted / consent.denied audit events
func TestConsent_GrantConsent_AuditEvent(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	auditSvc := services.NewAuditService(stores.Audit, obs)
	registry := newTestRegistry(stores)

	const uri = "https://mcp.example.com"
	seedMintResource(t, stores, "mcp-audit", "Audit MCP", uri,
		resource.Scope{Name: "tools/query", Description: "Query"},
	)

	consentSvc := services.NewConsentService(
		stores.ConsentGrant, stores.Session, stores.Client, registry, obs, auditSvc,
	)

	ctx := context.Background()
	now := time.Now().UTC()

	// Create client.
	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "Consent Test",
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

	// Seed user (FK on consent_grants.user_id → users.id).
	if err := seedUser(ctx, stores, "user-consent-42"); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// Create auth session.
	code := crypto.GenerateAuthCode()
	verifier := crypto.GenerateVerifier()
	sess := &session.AuthSession{
		ID:                  crypto.GenerateRandomString(16),
		ClientID:            c.ID,
		UserID:              "user-consent-42",
		RedirectURI:         "https://app.example.com/callback",
		Scope:               "tools/query",
		Resource:            uri,
		State:               "state-1",
		CodeHash:            crypto.HashSHA256(code),
		CodeChallenge:       crypto.ComputeS256Challenge(verifier),
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(session.AuthCodeTTL),
		CreatedAt:           now,
	}
	if err := stores.Session.Create(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Grant consent.
	_, err := consentSvc.GrantConsent(ctx, input.GrantConsentRequest{
		SessionID:      sess.ID,
		UserID:         "user-consent-42",
		ApprovedScopes: []string{"tools/query"},
		Remember:       false,
	})
	if err != nil {
		t.Fatalf("grant consent: %v", err)
	}

	// Verify audit event.
	events, err := auditSvc.Query(ctx, output.AuditFilter{
		Action: string(audit.ActionConsentGranted),
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(events) < 1 {
		t.Error("expected at least 1 consent.granted audit event")
	}
	if events[0].ActorID != "user-consent-42" {
		t.Errorf("audit actor_id: got %q, want %q", events[0].ActorID, "user-consent-42")
	}
	if events[0].ClientID != c.ID {
		t.Errorf("audit client_id: got %q, want %q", events[0].ClientID, c.ID)
	}
}

// Matrix: 18.6 — Consent scope escalation: approved scopes must be subset of requested
func TestConsent_ScopeEscalation_Rejected(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	registry := newTestRegistry(stores)

	const uri = "https://mcp.example.com"
	seedMintResource(t, stores, "mcp-escalate", "Escalate MCP", uri,
		resource.Scope{Name: "tools/query", Description: "Query"},
	)

	consentSvc := services.NewConsentService(
		stores.ConsentGrant, stores.Session, stores.Client, registry, obs, nil,
	)

	ctx := context.Background()
	now := time.Now().UTC()

	// Create client.
	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "Escalation Test",
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
	if err := seedUser(ctx, stores, "user-esc-1"); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// Create session requesting "tools/query" only.
	code := crypto.GenerateAuthCode()
	verifier := crypto.GenerateVerifier()
	sess := &session.AuthSession{
		ID:                  crypto.GenerateRandomString(16),
		ClientID:            c.ID,
		UserID:              "user-esc-1",
		RedirectURI:         "https://app.example.com/callback",
		Scope:               "tools/query",
		Resource:            uri,
		State:               "state-1",
		CodeHash:            crypto.HashSHA256(code),
		CodeChallenge:       crypto.ComputeS256Challenge(verifier),
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(session.AuthCodeTTL),
		CreatedAt:           now,
	}
	if err := stores.Session.Create(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Try to approve "tools/query tools/admin" — tools/admin was NOT requested.
	_, err := consentSvc.GrantConsent(ctx, input.GrantConsentRequest{
		SessionID:      sess.ID,
		UserID:         "user-esc-1",
		ApprovedScopes: []string{"tools/query", "tools/admin"},
		Remember:       false,
	})
	if err == nil {
		t.Fatal("approving scopes beyond requested should fail")
	}
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Errorf("expected ErrInvalidScope, got: %v", err)
	}
}

// Matrix: 18.6 — Consent scope narrowing accepted
func TestConsent_ScopeNarrowing_Accepted(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	registry := newTestRegistry(stores)

	const uri = "https://mcp.example.com"
	seedMintResource(t, stores, "mcp-narrow", "Narrow MCP", uri,
		resource.Scope{Name: "tools/query", Description: "Query"},
		resource.Scope{Name: "tools/create", Description: "Create"},
	)

	consentSvc := services.NewConsentService(
		stores.ConsentGrant, stores.Session, stores.Client, registry, obs, nil,
	)

	ctx := context.Background()
	now := time.Now().UTC()

	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "Narrowing Test",
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
	if err := seedUser(ctx, stores, "user-narrow-1"); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// Session requests "tools/query tools/create".
	code := crypto.GenerateAuthCode()
	verifier := crypto.GenerateVerifier()
	sess := &session.AuthSession{
		ID:                  crypto.GenerateRandomString(16),
		ClientID:            c.ID,
		UserID:              "user-narrow-1",
		RedirectURI:         "https://app.example.com/callback",
		Scope:               "tools/query tools/create",
		Resource:            uri,
		State:               "state-1",
		CodeHash:            crypto.HashSHA256(code),
		CodeChallenge:       crypto.ComputeS256Challenge(verifier),
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(session.AuthCodeTTL),
		CreatedAt:           now,
	}
	if err := stores.Session.Create(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Approve only "tools/query" (narrower subset) — should succeed.
	result, err := consentSvc.GrantConsent(ctx, input.GrantConsentRequest{
		SessionID:      sess.ID,
		UserID:         "user-narrow-1",
		ApprovedScopes: []string{"tools/query"},
		Remember:       false,
	})
	if err != nil {
		t.Fatalf("grant narrowed consent: %v", err)
	}
	if result.Code == "" {
		t.Error("expected auth code")
	}
}

func TestConsent_DenyConsent_AuditEvent(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	auditSvc := services.NewAuditService(stores.Audit, obs)
	registry := newTestRegistry(stores)

	consentSvc := services.NewConsentService(
		stores.ConsentGrant, stores.Session, stores.Client, registry, obs, auditSvc,
	)

	ctx := context.Background()

	// DenyConsent records the audit event and returns ErrConsentRequired.
	err := consentSvc.DenyConsent(ctx, "test-session-deny", "")
	if err == nil {
		t.Fatal("deny consent should return ErrConsentRequired")
	}

	// Verify audit event.
	events, err := auditSvc.Query(ctx, output.AuditFilter{
		Action: string(audit.ActionConsentDenied),
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(events) < 1 {
		t.Error("expected at least 1 consent.denied audit event")
	}
}

// ============================================================================
// Cross-user adversarial tests (ADV7, ADV6) — 2026-05-18 audit MEDIUM.
//
// Pre-fix: ConsentService.GrantConsent reads the session but never compares
// sess.UserID to req.UserID. Any logged-in user B can advance user A's
// authorization session by knowing/leaking the session_id. The consent grant
// is recorded under B, but the auth code is bound to sess.UserID = A, so the
// resulting token is issued for A — a classic confused-deputy plus an audit
// misattribution.
//
// The fixture exercises both GrantConsent and DenyConsent because a logged-in
// stranger should not be able to GRANT, DENY, or otherwise mutate someone
// else's pending authorization session.
// ============================================================================

// setupTwoUserFixture builds the minimal stores + service + two users + a
// session owned by user A. Returns the consent service, session, and stores so
// individual tests can call GrantConsent / DenyConsent and inspect state.
type twoUserFixture struct {
	stores  *sqlite.Stores
	svc     *services.ConsentService
	sess    *session.AuthSession
	client  *client.Client
	resURI  string
	userA   string
	userB   string
}

func setupTwoUserFixture(t *testing.T) *twoUserFixture {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	registry := newTestRegistry(stores)

	const uri = "https://mcp-crossuser.example.com"
	seedMintResource(t, stores, "mcp-crossuser", "Cross-User MCP", uri,
		resource.Scope{Name: "tools/query", Description: "Query"},
	)

	svc := services.NewConsentService(
		stores.ConsentGrant, stores.Session, stores.Client, registry, obs, nil,
	)

	ctx := context.Background()
	now := time.Now().UTC()

	const userA = "user-alice"
	const userB = "user-bob"
	if err := seedUser(ctx, stores, userA); err != nil {
		t.Fatalf("seed alice: %v", err)
	}
	if err := seedUser(ctx, stores, userB); err != nil {
		t.Fatalf("seed bob: %v", err)
	}

	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "Cross-User Test",
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

	code := crypto.GenerateAuthCode()
	verifier := crypto.GenerateVerifier()
	sess := &session.AuthSession{
		ID:                  crypto.GenerateRandomString(16),
		ClientID:            c.ID,
		UserID:              userA, // owned by Alice
		RedirectURI:         "https://app.example.com/callback",
		Scope:               "tools/query",
		Resource:            uri,
		State:               "state-cross",
		CodeHash:            crypto.HashSHA256(code),
		CodeChallenge:       crypto.ComputeS256Challenge(verifier),
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(session.AuthCodeTTL),
		CreatedAt:           now,
	}
	if err := stores.Session.Create(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	return &twoUserFixture{stores: stores, svc: svc, sess: sess, client: c, resURI: uri, userA: userA, userB: userB}
}

// Cross-user GrantConsent: Bob submits an approval for Alice's session.
// Must be rejected, AND the side effects must be absent (ADV6):
//   - no consent_grants row written for Bob OR Alice
//   - the session's code_hash MUST be unchanged so Alice's flow remains intact
func TestConsent_CrossUser_Grant_Rejected_NoSideEffects(t *testing.T) {
	fx := setupTwoUserFixture(t)
	ctx := context.Background()

	preCodeHash := fx.sess.CodeHash

	_, err := fx.svc.GrantConsent(ctx, input.GrantConsentRequest{
		SessionID:      fx.sess.ID,
		UserID:         fx.userB, // Bob, not Alice
		ApprovedScopes: []string{"tools/query"},
	})
	if err == nil {
		t.Fatal("cross-user GrantConsent must return an error")
	}

	// Side-effect 1: no consent grant written for either user. The
	// consent_grants table is keyed (user_id, client_id, resource_id);
	// neither row may exist.
	registry := newTestRegistry(fx.stores)
	res, rerr := registry.Resolve(ctx, fx.resURI)
	if rerr != nil {
		t.Fatalf("resolve resource: %v", rerr)
	}
	if g, _ := fx.stores.ConsentGrant.Get(ctx, fx.userB, fx.client.ID, res.ID); g != nil {
		t.Errorf("rejected cross-user attempt wrote a consent grant for Bob: %+v", g)
	}
	if g, _ := fx.stores.ConsentGrant.Get(ctx, fx.userA, fx.client.ID, res.ID); g != nil {
		t.Errorf("rejected cross-user attempt wrote a consent grant for Alice: %+v", g)
	}

	// Side-effect 2: the original session's code hash is unchanged. If the
	// cross-user attempt had progressed past the auth check, the service would
	// have called UpdateCodeHashAndScope and a new code would have been bound.
	got, gerr := fx.stores.Session.GetByID(ctx, fx.sess.ID)
	if gerr != nil {
		t.Fatalf("re-read session: %v", gerr)
	}
	if got.CodeHash != preCodeHash {
		t.Errorf("session code_hash mutated by rejected cross-user attempt")
	}

	// Side-effect 3: the session UserID was not silently overwritten.
	if got.UserID != fx.userA {
		t.Errorf("session UserID overwritten to %q (was %q)", got.UserID, fx.userA)
	}
}

// Cross-user DenyConsent: Bob denies Alice's session. Same threat shape —
// even though deny only deletes the session, Bob should not be able to abort
// Alice's flow.
//
// Pre-fix DenyConsent has no userID parameter at all, so any logged-in user
// can deny anyone's session. The fix adds the userID parameter and the same
// owner check.
func TestConsent_CrossUser_Deny_Rejected_SessionPreserved(t *testing.T) {
	fx := setupTwoUserFixture(t)
	ctx := context.Background()

	// Bob attempts to deny Alice's flow.
	if err := fx.svc.DenyConsent(ctx, fx.sess.ID, fx.userB); err == nil {
		t.Fatal("cross-user DenyConsent must return an error")
	}

	// Side-effect: the session row must still exist so Alice can complete.
	got, gerr := fx.stores.Session.GetByID(ctx, fx.sess.ID)
	if gerr != nil || got == nil {
		t.Fatalf("session must not be deleted by cross-user deny: err=%v got=%+v", gerr, got)
	}
}

// Positive regression: after Bob's failed cross-user grant attempt, Alice's
// legitimate grant still succeeds. This catches a "fix" that accidentally
// burns the session on the first failed attempt.
func TestConsent_CrossUser_Grant_AlicePathStillWorks(t *testing.T) {
	fx := setupTwoUserFixture(t)
	ctx := context.Background()

	// Bob tries first and fails.
	_, _ = fx.svc.GrantConsent(ctx, input.GrantConsentRequest{
		SessionID:      fx.sess.ID,
		UserID:         fx.userB,
		ApprovedScopes: []string{"tools/query"},
	})

	// Alice retries her own session.
	res, err := fx.svc.GrantConsent(ctx, input.GrantConsentRequest{
		SessionID:      fx.sess.ID,
		UserID:         fx.userA,
		ApprovedScopes: []string{"tools/query"},
	})
	if err != nil {
		t.Fatalf("alice's legitimate consent failed after bob's rejected attempt: %v", err)
	}
	if res == nil || res.Code == "" {
		t.Errorf("alice expected an auth code, got %+v", res)
	}
}

// Empty req.UserID — defense in depth. A request with no authenticated user
// must never advance a session even if the session has a UserID set.
func TestConsent_EmptyReqUser_Rejected(t *testing.T) {
	fx := setupTwoUserFixture(t)
	ctx := context.Background()

	_, err := fx.svc.GrantConsent(ctx, input.GrantConsentRequest{
		SessionID:      fx.sess.ID,
		UserID:         "",
		ApprovedScopes: []string{"tools/query"},
	})
	if err == nil {
		t.Fatal("empty req.UserID must be rejected — no anonymous consent")
	}
}

// seedUser inserts a minimal user row to satisfy the consent_grants.user_id
// foreign key constraint.
func seedUser(ctx context.Context, stores *sqlite.Stores, userID string) error {
	now := time.Now().UTC()
	return stores.User.Create(ctx, &user.User{
		ID:        userID,
		Email:     userID + "@example.test",
		Status:    user.StatusActive,
		Provider:  user.ProviderLocal,
		Version:   1,
		CreatedAt: now,
		UpdatedAt: now,
	})
}
