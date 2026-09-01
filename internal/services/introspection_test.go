//go:build integration

package services_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

const testIssuer = "http://localhost:8080"

// mockAuditRecorder captures audit events for testing.
type mockAuditRecorder struct {
	count  int
	events []audit.Event
}

func (m *mockAuditRecorder) Record(_ context.Context, e audit.Event) {
	m.count++
	m.events = append(m.events, e)
}

// introspectEnv holds the test environment for introspection tests.
type introspectEnv struct {
	svc      *services.IntrospectionService
	kp       *crypto.KeyPair
	clientID string
	audit    *mockAuditRecorder
	jwks     *mockJWKSBuild
	registry *services.ResourceRegistry

	// addClient and addResource close over the store handles so this file
	// never names an adapter or resource type — Gate 0 keeps integration
	// tests off those packages, and the allowlist is a one-way ratchet.
	addClient   func(t *testing.T, id, secret string, status client.Status)
	addResource func(t *testing.T, id, slug, uri string, runtimeClientIDs ...string)
}

func newIntrospectEnv(t *testing.T) *introspectEnv {
	t.Helper()

	stores := testdata.SetupTestStores(t)
	obs := testObs()

	// Create a signing key pair.
	kp, err := crypto.GenerateKeyPair("ES256", "test-kid-1")
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	// Create a test client (confidential).
	secretHash, err := crypto.HashBcrypt("test-secret")
	if err != nil {
		t.Fatalf("hash bcrypt: %v", err)
	}
	c := &client.Client{
		ID:           "introspect-client-1",
		SecretHash:   secretHash,
		RedirectURIs: []string{"http://localhost/callback"},
		Status:       client.StatusActive,
		IssuedAt:     time.Now(),
	}
	if err := stores.Client.Create(context.Background(), c); err != nil {
		t.Fatalf("create client: %v", err)
	}

	// Create test user referenced in validClaims() Subject field.
	now := time.Now().UTC()
	testUser := &user.User{
		ID:        "user-1",
		Email:     "user1@example.com",
		Role:      user.RoleUser,
		Status:    user.StatusActive,
		Provider:  user.ProviderLocal,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := stores.User.Create(context.Background(), testUser); err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Mock JWKS provider.
	jwksMock := &mockJWKSBuild{kp: kp}

	auditor := &mockAuditRecorder{}
	svc := services.NewIntrospectionService(
		jwksMock, stores.Revocation, stores.MachineToken, stores.Client, stores.User,
		staticIssuerForTest(testIssuer), obs, auditor,
	)
	registry := services.NewResourceRegistry(stores.Resource, stores.BrokerProvider, obs)
	svc.WithResourceRegistry(registry)

	return &introspectEnv{
		svc:      svc,
		kp:       kp,
		clientID: c.ID,
		audit:    auditor,
		jwks:     jwksMock,
		registry: registry,
		addClient: func(t *testing.T, id, secret string, status client.Status) {
			t.Helper()
			testdata.CreateClient(t, stores, id, secret, status)
		},
		addResource: func(t *testing.T, id, slug, uri string, runtimeClientIDs ...string) {
			t.Helper()
			testdata.CreateMintResource(t, stores, id, slug, uri, runtimeClientIDs...)
		},
	}
}

// wantInvalidClient asserts the service refused the caller outright. Gate 0
// keeps this file off internal/domain, so match the rendered error rather
// than errors.Is(err, domain.ErrInvalidClient).
func wantInvalidClient(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected client authentication to fail, got nil error")
	}
	if !strings.Contains(err.Error(), "client authentication failed") {
		t.Fatalf("got %v, want invalid_client", err)
	}
}

// wantDeniedFor asserts the single denial row names the expected reason.
//
// Asserting only active=false is what let an unrelated gate silently take over
// TestIntrospect_SuspendedClient_Inactive: several branches produce that body,
// so the test kept passing while covering nothing. Pinning the reason means a
// check that refuses earlier turns the test red instead of inheriting it.
func (e *introspectEnv) wantDeniedFor(t *testing.T, reason string) {
	t.Helper()
	wantDeniedFor(t, e.audit, reason)
}

// wantDeniedFor is the standalone form, for tests that build their own service
// and so carry their own recorder.
func wantDeniedFor(t *testing.T, rec *mockAuditRecorder, reason string) {
	t.Helper()
	var denied []audit.Event
	for _, ev := range rec.events {
		if ev.Action == audit.ActionTokenIntrospectDenied {
			denied = append(denied, ev)
		}
	}
	if len(denied) != 1 {
		t.Fatalf("denied audit events = %d, want 1", len(denied))
	}
	if !strings.Contains(denied[0].Detail, "reason="+reason) {
		t.Fatalf("refused by %q, want reason=%s — a different check rejected this",
			denied[0].Detail, reason)
	}
}

// deniedEvents returns the audit rows recorded for non-successful
// introspection calls.
func (e *introspectEnv) deniedEvents() []audit.Event {
	var out []audit.Event
	for _, ev := range e.audit.events {
		if ev.Action == audit.ActionTokenIntrospectDenied {
			out = append(out, ev)
		}
	}
	return out
}

// mockJWKSBuild implements services.JWKSBuildProvider.
type mockJWKSBuild struct {
	kp  *crypto.KeyPair
	err error // when set, stands in for an AS that cannot assemble its keys
}

func (m *mockJWKSBuild) BuildJWKS(_ context.Context) (*jose.JSONWebKeySet, error) {
	if m.err != nil {
		return nil, m.err
	}
	jwks := crypto.BuildJWKS(m.kp)
	return &jwks, nil
}

func signTestToken(t *testing.T, kp *crypto.KeyPair, claims crypto.AccessTokenClaims) string {
	t.Helper()
	token, err := crypto.SignAccessToken(kp, claims)
	if err != nil {
		t.Fatalf("sign access token: %v", err)
	}
	return token
}

func validClaims() crypto.AccessTokenClaims {
	now := time.Now().UTC()
	return crypto.AccessTokenClaims{
		Issuer:   testIssuer,
		Subject:  "user-1",
		Audience: []string{"https://resource.example.com"},
		ClientID: "introspect-client-1",
		Scope:    "tools/read tools/write",
		JTI:      crypto.GenerateRandomString(16),
		IssuedAt: now.Unix(),
		Expiry:   now.Add(15 * time.Minute).Unix(),
	}
}

func TestIntrospect_ValidToken_Active(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()

	claims := validClaims()
	token := signTestToken(t, env.kp, claims)

	resp, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     env.clientID,
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if !resp.Active {
		t.Fatal("expected active=true")
	}
	if resp.Sub != "user-1" {
		t.Errorf("Sub = %q, want user-1", resp.Sub)
	}
	if resp.ClientID != "introspect-client-1" {
		t.Errorf("ClientID = %q, want introspect-client-1", resp.ClientID)
	}
	if resp.Scope != "tools/read tools/write" {
		t.Errorf("Scope = %q, want 'tools/read tools/write'", resp.Scope)
	}
	if resp.Iss != testIssuer {
		t.Errorf("Iss = %q, want %q", resp.Iss, testIssuer)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want Bearer", resp.TokenType)
	}
	if resp.Jti != claims.JTI {
		t.Errorf("Jti = %q, want %q", resp.Jti, claims.JTI)
	}
}

func TestIntrospect_ExpiredToken_Inactive(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()

	claims := validClaims()
	claims.Expiry = time.Now().Add(-1 * time.Hour).Unix()
	token := signTestToken(t, env.kp, claims)

	resp, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     env.clientID,
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if resp.Active {
		t.Fatal("expected active=false for expired token")
	}
}

func TestIntrospect_RevokedJTI_Inactive(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()
	stores := testdata.SetupTestStores(t)

	// Create a fresh env with this store's revocation store.
	jwksMock := &mockJWKSBuild{kp: env.kp}

	// Create client in the new store.
	secretHash, _ := crypto.HashBcrypt("test-secret")
	c := &client.Client{
		ID:           "introspect-client-1",
		SecretHash:   secretHash,
		RedirectURIs: []string{"http://localhost/callback"},
		Status:       client.StatusActive,
		IssuedAt:     time.Now(),
	}
	_ = stores.Client.Create(ctx, c)

	// token_families.user_id is FK-enforced.
	testdata.EnsureUser(t, stores.User, "user-1")

	auditor := &mockAuditRecorder{}
	svc := services.NewIntrospectionService(
		jwksMock, stores.Revocation, stores.MachineToken, stores.Client, nil,
		staticIssuerForTest(testIssuer), testObs(), auditor,
	)

	// Family must exist due to FK constraint on access_token_jtis.family_id.
	if err := stores.Token.CreateFamily(ctx, &token.Family{
		ID:        "family-1",
		ClientID:  "introspect-client-1",
		UserID:    "user-1",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateFamily: %v", err)
	}

	claims := validClaims()
	signedToken := signTestToken(t, env.kp, claims)

	// Track the JTI, then revoke it.
	if err := stores.Revocation.TrackJTI(ctx, claims.JTI, "family-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("TrackJTI: %v", err)
	}
	if err := stores.Revocation.RevokeJTI(ctx, claims.JTI); err != nil {
		t.Fatalf("RevokeJTI: %v", err)
	}

	resp, err := svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        signedToken,
		ClientID:     "introspect-client-1",
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if resp.Active {
		t.Fatal("expected active=false for revoked JTI")
	}
	wantDeniedFor(t, auditor, "token_revoked")
}

func TestIntrospect_InvalidSignature_Inactive(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()

	// Sign with a different key.
	otherKP, _ := crypto.GenerateKeyPair("ES256", "other-kid")
	claims := validClaims()
	token := signTestToken(t, otherKP, claims)

	resp, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     env.clientID,
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if resp.Active {
		t.Fatal("expected active=false for token with unknown kid")
	}
}

func TestIntrospect_SuspendedClient_Inactive(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	ctx := context.Background()

	kp, _ := crypto.GenerateKeyPair("ES256", "test-kid-1")
	jwksMock := &mockJWKSBuild{kp: kp}

	// Create a requesting client (active).
	secretHash, _ := crypto.HashBcrypt("test-secret")
	reqClient := &client.Client{
		ID:           "requesting-client",
		SecretHash:   secretHash,
		RedirectURIs: []string{"http://localhost/callback"},
		Status:       client.StatusActive,
		IssuedAt:     time.Now(),
	}
	_ = stores.Client.Create(ctx, reqClient)

	// Create the issuing client (suspended).
	issuingClient := &client.Client{
		ID:           "issuing-client-suspended",
		RedirectURIs: []string{"http://localhost/callback"},
		Status:       client.StatusSuspended,
		IssuedAt:     time.Now(),
	}
	_ = stores.Client.Create(ctx, issuingClient)

	// The requesting client has to clear the entitlement gate before the
	// issuing-client check can run at all, so bind it to the Resource the
	// token is audienced at. Without this the gate refuses first and the
	// branch under test is never reached — the test would still pass, for the
	// wrong reason.
	obs := testObs()
	testdata.CreateMintResource(t, stores, "res-suspended", "echo-mcp",
		"https://resource.example.com", "requesting-client")

	auditor := &mockAuditRecorder{}
	svc := services.NewIntrospectionService(
		jwksMock, stores.Revocation, stores.MachineToken, stores.Client, nil,
		staticIssuerForTest(testIssuer), obs, auditor,
	)
	svc.WithResourceRegistry(services.NewResourceRegistry(stores.Resource, stores.BrokerProvider, obs))

	claims := validClaims()
	claims.ClientID = "issuing-client-suspended"
	token := signTestToken(t, kp, claims)

	resp, err := svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     "requesting-client",
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if resp.Active {
		t.Fatal("expected active=false for suspended issuing client")
	}

	// Assert *why*. Checking only active=false is what let an unrelated gate
	// silently take this test over: any future check that refuses earlier will
	// now turn it red instead of leaving it green and empty.
	if len(auditor.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(auditor.events))
	}
	if !strings.Contains(auditor.events[0].Detail, "reason=issuing_client_inactive") {
		t.Fatalf("refused by %q — the issuing-client branch is not what rejected this",
			auditor.events[0].Detail)
	}
}

func TestIntrospect_InvalidClientAuth_Error(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()

	claims := validClaims()
	token := signTestToken(t, env.kp, claims)

	_, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     env.clientID,
		ClientSecret: "wrong-secret",
	})
	if err == nil {
		t.Fatal("expected error for invalid client auth")
	}
}

func TestIntrospect_NonJWT_Inactive(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()

	resp, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        "this-is-not-a-jwt",
		ClientID:     env.clientID,
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if resp.Active {
		t.Fatal("expected active=false for non-JWT token")
	}
}

func TestIntrospect_DisabledUser_Inactive(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()

	claims := validClaims()
	token := signTestToken(t, env.kp, claims)

	// Disable the user (created as active in newIntrospectEnv).
	stores := testdata.SetupTestStores(t)
	// We need a fresh env with a user store that has the disabled user.
	kp := env.kp
	jwksMock := &mockJWKSBuild{kp: kp}

	secretHash, _ := crypto.HashBcrypt("test-secret")
	c := &client.Client{
		ID:           "introspect-client-1",
		SecretHash:   secretHash,
		RedirectURIs: []string{"http://localhost/callback"},
		Status:       client.StatusActive,
		IssuedAt:     time.Now(),
	}
	_ = stores.Client.Create(ctx, c)

	// Create user as disabled.
	now := time.Now().UTC()
	disabledUser := &user.User{
		ID:        "user-1",
		Email:     "user1@example.com",
		Role:      user.RoleUser,
		Status:    user.StatusDisabled,
		Provider:  user.ProviderLocal,
		CreatedAt: now,
		UpdatedAt: now,
	}
	_ = stores.User.Create(ctx, disabledUser)

	auditor := &mockAuditRecorder{}
	svc := services.NewIntrospectionService(
		jwksMock, stores.Revocation, stores.MachineToken, stores.Client, stores.User,
		staticIssuerForTest(testIssuer), testObs(), auditor,
	)

	resp, err := svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     "introspect-client-1",
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if resp.Active {
		t.Fatal("expected active=false for disabled user")
	}
	wantDeniedFor(t, auditor, "subject_inactive")
}

func TestIntrospect_FutureNBF_Inactive(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()

	claims := validClaims()
	claims.NotBefore = time.Now().Add(1 * time.Hour).Unix() // not yet valid
	token := signTestToken(t, env.kp, claims)

	resp, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     env.clientID,
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if resp.Active {
		t.Fatal("expected active=false for token with future nbf")
	}
}

func TestIntrospect_AuditRecorded(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	ctx := context.Background()

	kp, _ := crypto.GenerateKeyPair("ES256", "test-kid-1")
	jwksMock := &mockJWKSBuild{kp: kp}

	secretHash, _ := crypto.HashBcrypt("test-secret")
	c := &client.Client{
		ID:           "audit-client",
		SecretHash:   secretHash,
		RedirectURIs: []string{"http://localhost/callback"},
		Status:       client.StatusActive,
		IssuedAt:     time.Now(),
	}
	_ = stores.Client.Create(ctx, c)

	auditMock := &mockAuditRecorder{}
	svc := services.NewIntrospectionService(
		jwksMock, stores.Revocation, stores.MachineToken, stores.Client, nil,
		staticIssuerForTest(testIssuer), testObs(), auditMock,
	)

	claims := validClaims()
	claims.ClientID = "audit-client"
	token := signTestToken(t, kp, claims)

	resp, err := svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     "audit-client",
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if !resp.Active {
		t.Fatal("expected active=true")
	}
	if auditMock.count == 0 {
		t.Error("expected audit event to be recorded")
	}
}

// --- ownership, caller standing, and negative-path auditing ---

// TestIntrospect_ForeignClient_Inactive pins the hole this ticket closes: a
// client that neither issued the token nor serves its audience learns nothing.
func TestIntrospect_ForeignClient_Inactive(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()
	env.addClient(t, "stranger", "stranger-secret", client.StatusActive)

	token := signTestToken(t, env.kp, validClaims())

	resp, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     "stranger",
		ClientSecret: "stranger-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if resp.Active {
		t.Fatal("a foreign client must not learn the token is active")
	}
	// RFC 7662 §4: an inactive response carries no other claim, which is also
	// what keeps "not yours" indistinguishable from "not valid".
	if resp.Sub != "" || resp.ClientID != "" || resp.Scope != "" || resp.Jti != "" {
		t.Errorf("inactive response leaked claims: %+v", resp)
	}
	denied := env.deniedEvents()
	if len(denied) != 1 {
		t.Fatalf("denied audit events = %d, want 1", len(denied))
	}
	if denied[0].ClientID != "stranger" {
		t.Errorf("denied event client_id = %q, want stranger", denied[0].ClientID)
	}
}

// TestIntrospect_SuspendedCaller_InvalidClient covers the gap the audit missed:
// suspending a client used to leave its introspection access untouched.
func TestIntrospect_SuspendedCaller_InvalidClient(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()
	env.addClient(t, "suspended-caller", "sus-secret", client.StatusSuspended)

	token := signTestToken(t, env.kp, validClaims())

	_, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     "suspended-caller",
		ClientSecret: "sus-secret",
	})
	wantInvalidClient(t, err)
	if len(env.deniedEvents()) != 1 {
		t.Errorf("a refused caller must leave an audit row, got %d", len(env.deniedEvents()))
	}
}

// TestIntrospect_PublicCaller_InvalidClient enforces RFC 6749 §2.3: a
// secret-less client carries no identity the ownership check can stand on.
// This is what the discovery document has always advertised — introspection's
// auth-method list omits "none".
func TestIntrospect_PublicCaller_InvalidClient(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()
	env.addClient(t, "public-caller", "", client.StatusActive)

	claims := validClaims()
	claims.ClientID = "public-caller" // even its own token is off limits
	token := signTestToken(t, env.kp, claims)

	_, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:    token,
		ClientID: "public-caller",
	})
	wantInvalidClient(t, err)
}

// TestIntrospect_ResourceServer_Authorized_Active covers the canonical RFC 7662
// caller: a resource server asking about a token minted for it, which is never
// the token's own client.
func TestIntrospect_ResourceServer_Authorized_Active(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()
	env.addClient(t, "rs-client", "rs-secret", client.StatusActive)
	env.addResource(t, "res-1", "echo-mcp", "https://resource.example.com", "rs-client")

	token := signTestToken(t, env.kp, validClaims())

	resp, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     "rs-client",
		ClientSecret: "rs-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if !resp.Active {
		t.Fatal("the resource server named in aud must be able to introspect")
	}
	if resp.ClientID != "introspect-client-1" {
		t.Errorf("ClientID = %q, want the token's owner", resp.ClientID)
	}
}

// TestIntrospect_ResourceServer_Unbound_Inactive pins the fail-closed half:
// without policy.runtime.client_ids the caller speaks for no Resource.
func TestIntrospect_ResourceServer_Unbound_Inactive(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()
	env.addClient(t, "rs-client", "rs-secret", client.StatusActive)
	env.addResource(t, "res-1", "echo-mcp", "https://resource.example.com")

	token := signTestToken(t, env.kp, validClaims())

	resp, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     "rs-client",
		ClientSecret: "rs-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if resp.Active {
		t.Fatal("an unbound client must not introspect on the Resource's behalf")
	}
	env.wantDeniedFor(t, "caller_not_authorized_for_token")
}

// TestIntrospect_ResourceServer_LegacyConvention_Active keeps deployments on
// the retired slug==client_id convention working for one release, mirroring
// TokenExchangeService.resolveActorMCP. Remove alongside that fallback.
//
// Both cases are covered because ResourceRegistry.Resolve matches slug exact OR
// uri exact: the slug case is the one the CHANGELOG's compatibility promise
// names, and the uri case is what the Go SDK demo produces by defaulting
// CLIENT_ID to the resource URL. Narrowing the fallback to one of them must
// turn this test red, not leave it green.
func TestIntrospect_ResourceServer_LegacyConvention_Active(t *testing.T) {
	const resourceURI = "https://resource.example.com"

	cases := []struct {
		name     string
		clientID string
	}{
		{"client_id equals slug", "echo-mcp"},
		{"client_id equals uri", resourceURI},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newIntrospectEnv(t)
			ctx := context.Background()
			env.addClient(t, tc.clientID, "legacy-secret", client.StatusActive)
			env.addResource(t, "res-1", "echo-mcp", resourceURI)

			token := signTestToken(t, env.kp, validClaims())

			resp, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
				Token:        token,
				ClientID:     tc.clientID,
				ClientSecret: "legacy-secret",
			})
			if err != nil {
				t.Fatalf("IntrospectToken: %v", err)
			}
			if !resp.Active {
				t.Fatal("the legacy convention must still resolve")
			}
		})
	}
}

// TestIntrospect_NegativePath_Audited covers the inverted audit trail the audit
// flagged: probing that yields negatives used to leave no row at all.
func TestIntrospect_NegativePath_Audited(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()

	resp, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        "not-a-token",
		ClientID:     env.clientID,
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if resp.Active {
		t.Fatal("expected active=false for garbage")
	}
	denied := env.deniedEvents()
	if len(denied) != 1 {
		t.Fatalf("denied audit events = %d, want 1", len(denied))
	}
	if !strings.Contains(denied[0].Detail, "reason=invalid_token") {
		t.Errorf("denied event details = %q, want reason=invalid_token", denied[0].Detail)
	}
}

// TestIntrospect_DenialReasonsAreGreppable pins the audit Detail contract: the
// canonical form is space-separated key=value pairs, so a reason carrying a
// space would split across two fields and break every query in
// docs/reference/audit-events.md.
func TestIntrospect_DenialReasonsAreGreppable(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()
	env.addClient(t, "stranger", "stranger-secret", client.StatusActive)

	token := signTestToken(t, env.kp, validClaims())

	// One client-authentication refusal and one post-verification refusal, so
	// both helpers are hit. The credential-free refusals are deliberately not
	// used here: they write no row at all
	// (see TestIntrospect_AuditedRefusals_AreCredentialed).
	_, _ = env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token: token, ClientID: env.clientID, ClientSecret: "wrong-secret",
	})
	_, _ = env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token: token, ClientID: "stranger", ClientSecret: "stranger-secret",
	})

	denied := env.deniedEvents()
	if len(denied) != 2 {
		t.Fatalf("denied audit events = %d, want 2", len(denied))
	}
	for _, ev := range denied {
		for _, field := range strings.Fields(ev.Detail) {
			if !strings.Contains(field, "=") {
				t.Errorf("detail %q is not key=value greppable (field %q)", ev.Detail, field)
			}
		}
	}
}

// TestIntrospect_FrontedMintToken_InactiveForEveryone documents a shape that
// predates this change: the fronted Mint dispatch issues a token whose
// client_id claim is the source Resource's slug rather than an OAuth
// client_id, and the issuing-client lookup resolves that claim against the
// client store. It finds nothing, so such a token reports inactive to every
// caller — the entitlement gate never decides it.
//
// Pinned so that a later change teaching that lookup about slug-shaped
// client_ids is a deliberate one, made with this test in hand.
func TestIntrospect_FrontedMintToken_InactiveForEveryone(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()
	env.addClient(t, "exchange-agent", "agent-secret", client.StatusActive)
	env.addResource(t, "res-1", "echo-mcp", "https://resource.example.com", "exchange-agent")

	claims := validClaims()
	claims.ClientID = "fronted-source-slug" // a Resource slug, not a client_id
	token := signTestToken(t, env.kp, claims)

	// The caller is a runtime client of the Resource in aud, so it clears the
	// entitlement gate — and is still refused, one check later.
	resp, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     "exchange-agent",
		ClientSecret: "agent-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if resp.Active {
		t.Fatal("expected inactive: client_id names no registered client")
	}

	denied := env.deniedEvents()
	if len(denied) != 1 {
		t.Fatalf("denied audit events = %d, want 1", len(denied))
	}
	if !strings.Contains(denied[0].Detail, "reason=issuing_client_inactive") {
		t.Errorf("refused by %q; the entitlement gate is not what rejects these",
			denied[0].Detail)
	}
}

// TestIntrospect_ServerFault_NotAudited pins that an AS-side failure reports the
// token inactive without writing a denial row.
//
// The audit trail exists so that probing leaves a mark. A JWKS that cannot be
// assembled is not probing — the caller did nothing wrong and the server failed
// — and during such an outage every call takes this path, so auditing it would
// bury the signal under the incident and amplify writes at the worst moment.
func TestIntrospect_ServerFault_NotAudited(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()
	env.jwks.err = errors.New("signing keys unavailable")

	resp, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        signTestToken(t, env.kp, validClaims()),
		ClientID:     env.clientID,
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if resp.Active {
		t.Fatal("expected active=false when the keys cannot be assembled")
	}
	if got := env.deniedEvents(); len(got) != 0 {
		t.Errorf("a server fault must not be recorded as a caller denial, got %q", got[0].Detail)
	}
}

// TestIntrospect_ResourceServer_BoundToTwoResources_Active covers the multi-tier
// deployment runtime-client-binding.md tells operators to configure: one OAuth
// client acting AS more than one Resource.
//
// Resolving from the caller cannot serve that shape — "which Resource does this
// client serve?" has two answers and the lookup reports it ambiguous — so the
// check runs from the token's aud instead, where the question has exactly one.
func TestIntrospect_ResourceServer_BoundToTwoResources_Active(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()
	env.addClient(t, "rs-client", "rs-secret", client.StatusActive)
	env.addResource(t, "res-1", "echo-mcp", "https://resource.example.com", "rs-client")
	env.addResource(t, "res-2", "other-mcp", "https://other.example.com", "rs-client")

	token := signTestToken(t, env.kp, validClaims()) // aud = https://resource.example.com

	resp, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     "rs-client",
		ClientSecret: "rs-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if !resp.Active {
		t.Fatal("a client bound to two Resources must still introspect tokens for either")
	}
}

// TestIntrospect_ResourceLookupFails_NotAudited keeps a resources-store outage
// from being filed under the probing signal.
//
// caller_not_authorized_for_token is the reason operators grep for a scan.
// Recording it when the store is down would name every legitimate resource
// server as a prober, and would do so once per request for the duration of the
// incident — the misattribution inactiveServerFault exists to prevent.
func TestIntrospect_ResourceLookupFails_NotAudited(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()
	env.addClient(t, "rs-client", "rs-secret", client.StatusActive)
	env.svc.WithResourceRegistry(testdata.NewUnavailableResourceResolver())

	resp, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        signTestToken(t, env.kp, validClaims()),
		ClientID:     "rs-client",
		ClientSecret: "rs-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if resp.Active {
		t.Fatal("expected inactive when the AS cannot resolve the audience")
	}
	if got := env.deniedEvents(); len(got) != 0 {
		t.Errorf("a store failure must not be audited as a caller denial, got %q", got[0].Detail)
	}
}

// TestIntrospect_AmbiguousResource_OwnReason pins that an operator mistake is
// refused under its own reason rather than the probing signal. It still denies:
// guessing which of two Resources was meant is exactly what must not happen on
// an entitlement check.
func TestIntrospect_AmbiguousResource_OwnReason(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()
	env.addClient(t, "rs-client", "rs-secret", client.StatusActive)
	env.svc.WithResourceRegistry(testdata.NewAmbiguousResourceResolver())

	resp, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        signTestToken(t, env.kp, validClaims()),
		ClientID:     "rs-client",
		ClientSecret: "rs-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if resp.Active {
		t.Fatal("an ambiguous binding must not resolve to a guess")
	}
	denied := env.deniedEvents()
	if len(denied) != 1 {
		t.Fatalf("denied audit events = %d, want 1", len(denied))
	}
	if !strings.Contains(denied[0].Detail, "reason=ambiguous_runtime_binding") {
		t.Errorf("detail = %q, want reason=ambiguous_runtime_binding", denied[0].Detail)
	}
}

// TestIntrospect_IssuerAudience_NotResolvedAsResource pins that a resource-less
// machine token — which carries aud=[issuer] — is never matched against a
// Resource registered under the issuer URL.
//
// Without the skip, such a Resource's runtime clients could introspect every
// resource-less machine token in the deployment.
func TestIntrospect_IssuerAudience_NotResolvedAsResource(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()
	env.addClient(t, "rs-client", "rs-secret", client.StatusActive)
	// A Resource registered under the issuer URL — the trap.
	env.addResource(t, "res-issuer", "issuer-shaped", testIssuer, "rs-client")

	claims := validClaims()
	claims.Audience = []string{testIssuer} // as mint_issuer emits for a resource-less token
	token := signTestToken(t, env.kp, claims)

	resp, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     "rs-client",
		ClientSecret: "rs-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if resp.Active {
		t.Fatal("aud=issuer names the AS, not a Resource: it must not confer entitlement")
	}
	// Without the reason, this would also pass if the Resource simply failed to
	// be created — i.e. if the trap it sets up were never armed.
	env.wantDeniedFor(t, "caller_not_authorized_for_token")
}

// TestIntrospect_StoreErrorOnOneAudience_StillAuthorizes covers a token with two
// audiences where the caller is bound to the second: a transient failure
// resolving the first must not refuse a caller the AS can still authorize.
func TestIntrospect_StoreErrorOnOneAudience_StillAuthorizes(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()
	env.addClient(t, "rs-client", "rs-secret", client.StatusActive)
	env.addResource(t, "res-2", "second-mcp", "https://second.example.com", "rs-client")
	env.svc.WithResourceRegistry(testdata.NewFlakyResourceResolver(
		env.registry, "https://first.example.com"))

	claims := validClaims()
	claims.Audience = []string{"https://first.example.com", "https://second.example.com"}
	token := signTestToken(t, env.kp, claims)

	resp, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     "rs-client",
		ClientSecret: "rs-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if !resp.Active {
		t.Fatal("a failure on one audience must not refuse a caller another audience authorizes")
	}
}

// TestIntrospect_AuditedRefusals_AreCredentialed pins which client-authentication
// refusals reach the audit log, and the axis the split is drawn on.
//
// A refusal earns a row only if the caller had to prove something to reach it.
// The three credential-free ones would otherwise let an anonymous loop drive a
// synchronous indexed INSERT per request — and because a public client_id
// travels in the authorize URL, an attacker could aim those writes at a chosen
// client's audit trail rather than merely at the table.
//
// Table-driven so that moving a reason across the line is a visible edit here
// rather than a silent change of behaviour.
func TestIntrospect_AuditedRefusals_AreCredentialed(t *testing.T) {
	cases := []struct {
		name     string
		clientID string
		secret   string
		setup    func(t *testing.T, env *introspectEnv)
		audited  bool
		reason   string
	}{
		{
			name:     "unrecognized client_id, no credential",
			clientID: strings.Repeat("x", 4096), // the shape a flood would take
			secret:   "whatever",
			setup:    func(*testing.T, *introspectEnv) {},
		},
		{
			name:     "public client, no credential and a public id",
			clientID: "known-public",
			setup: func(t *testing.T, env *introspectEnv) {
				env.addClient(t, "known-public", "", client.StatusActive)
			},
		},
		{
			name:     "omitted secret, no credential",
			clientID: "known-confidential",
			setup: func(t *testing.T, env *introspectEnv) {
				env.addClient(t, "known-confidential", "right-secret", client.StatusActive)
			},
		},
		{
			name:     "wrong secret, pays a full comparison",
			clientID: "known-confidential",
			secret:   "wrong-secret",
			setup: func(t *testing.T, env *introspectEnv) {
				env.addClient(t, "known-confidential", "right-secret", client.StatusActive)
			},
			audited: true,
			reason:  "invalid_client_secret",
		},
		{
			name:     "suspended caller, reached only once the secret verified",
			clientID: "suspended-caller",
			secret:   "sus-secret",
			setup: func(t *testing.T, env *introspectEnv) {
				env.addClient(t, "suspended-caller", "sus-secret", client.StatusSuspended)
			},
			audited: true,
			reason:  "client_not_active",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newIntrospectEnv(t)
			tc.setup(t, env)

			_, err := env.svc.IntrospectToken(context.Background(), input.IntrospectRequest{
				Token:        signTestToken(t, env.kp, validClaims()),
				ClientID:     tc.clientID,
				ClientSecret: tc.secret,
			})
			wantInvalidClient(t, err)

			denied := env.deniedEvents()
			if !tc.audited {
				if len(denied) != 0 {
					t.Fatalf("a credential-free refusal must not be persisted, got %q", denied[0].Detail)
				}
				return
			}
			if len(denied) != 1 {
				t.Fatalf("denied audit events = %d, want 1", len(denied))
			}
			if !strings.Contains(denied[0].Detail, "reason="+tc.reason) {
				t.Errorf("detail = %q, want reason=%s", denied[0].Detail, tc.reason)
			}
		})
	}
}
