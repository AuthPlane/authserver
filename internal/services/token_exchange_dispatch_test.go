//go:build integration

package services_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/internal/adapters/keyfile"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/brokerproto"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

// -------------------------------------------------------------------
//  dispatch-test harness. Builds a TokenExchangeService with the
// unified-dispatch dependencies wired (registry + consent + mint + broker)
// on top of a shared sqlite test DB so the live ResourceRegistry,
// ConsentGrantStore, BrokerGrantStore, and IssuanceStore exercise their
// actual SQL paths. Mint dispatch uses a real MintIssuer (signed JWT
// verifiable in-test); Broker dispatch uses a real BrokerIssuer with a
// stub brokerproto.OAuth adapter and a fake DataEncryptor.
// -------------------------------------------------------------------

type dispatchSetup struct {
	*teTestSetup

	// Direct handles to seed the unified tables and assert against
	// dispatch behavior.
	stores      *storeBundle
	mintIssuer  *services.MintIssuer
	brokerStub  *dispatchStubAdapter
	encryptor   *dispatchEncryptor
	registry    *services.ResourceRegistry
	provider    *resource.BrokerProvider // seeded provider for broker tests
	mintTarget  *resource.Resource       // seeded mint resource for mint tests
	brokerTgt   *resource.Resource       // seeded broker resource for broker tests
	actorMintRC *resource.Resource       // actor MCP registered as mint resource (broker attestation)
}

type storeBundle struct {
	resources    output.ResourceStore
	providers    output.BrokerProviderStore
	consents     output.ConsentGrantStore
	brokerGrants output.BrokerGrantStore
}

func newDispatchSetup(t *testing.T) *dispatchSetup {
	t.Helper()
	return newDispatchSetupWithConfig(t, output.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})
}

func newDispatchSetupWithConfig(t *testing.T, cfg output.TokenExchangeConfig) *dispatchSetup {
	t.Helper()

	stores := testdata.SetupTestStores(t)
	obs := testObs()

	dir := t.TempDir()
	ks, err := keyfile.New(dir, obs)
	if err != nil {
		t.Fatalf("keyfile: %v", err)
	}
	jwksSvc := services.NewJWKSService(ks, nil, "ES256", obs)
	auditSvc := services.NewAuditService(stores.Audit, obs)

	bundle := &storeBundle{
		resources:    stores.Resource,
		providers:    stores.BrokerProvider,
		consents:     stores.ConsentGrant,
		brokerGrants: stores.BrokerGrant,
	}

	mintIssuer := services.NewMintIssuer(jwksSvc, stores.Issuance, staticIssuerForTest(teIssuer), obs)

	enc := &dispatchEncryptor{}
	stub := &dispatchStubAdapter{name: "oauth"}
	bpReg := brokerproto.NewRegistry()
	if err := bpReg.Register(stub); err != nil {
		t.Fatalf("register stub broker adapter: %v", err)
	}
	brokerIssuer := services.NewBrokerIssuer(
		stores.BrokerGrant, enc, stores.Issuance,
		bpReg, obs, auditSvc,
	)

	registry := services.NewResourceRegistry(stores.Resource, stores.BrokerProvider, obs)

	svc := services.NewTokenExchangeService(
		stores.Client, stores.MachineToken, jwksSvc, jwksSvc, stores.Revocation,
		staticIssuerForTest(teIssuer), static.NewTokenExchangeConfigProvider(cfg),
		registry, stores.ConsentGrant, mintIssuer, brokerIssuer,
		obs, auditSvc,
	)

	sk, err := jwksSvc.GetSigningKey(context.Background())
	if err != nil {
		t.Fatalf("get signing key: %v", err)
	}
	kp := &crypto.KeyPair{
		PrivateKey: sk.PrivateKey,
		PublicKey:  sk.PublicKey,
		Algorithm:  jose.SignatureAlgorithm(sk.Algorithm),
		KeyID:      sk.KeyID,
	}

	return &dispatchSetup{
		teTestSetup: &teTestSetup{
			svc:      svc,
			jwksSvc:  jwksSvc,
			auditSvc: auditSvc,
			h:        &testdata.TestHelper{Stores: stores},
			obs:      obs,
			kp:       kp,
		},
		stores:     bundle,
		mintIssuer: mintIssuer,
		brokerStub: stub,
		encryptor:  enc,
		registry:   registry,
	}
}

// seedMintResource creates a mint Resource with the given slug and scope
// catalog. URI is derived from slug for test simplicity.
func (s *dispatchSetup) seedMintResource(t *testing.T, slug string, scopes []string, allowedClientIDs []string) *resource.Resource {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	scs := make([]resource.Scope, len(scopes))
	for i, name := range scopes {
		scs[i] = resource.Scope{Name: name}
	}
	r := &resource.Resource{
		ID:          "res-" + slug,
		Slug:        slug,
		DisplayName: "Mint " + slug,
		URI:         "https://" + slug + ".test.example.com",
		BackendKind: resource.BackendMint,
		Scopes:      scs,
		Policy: resource.Policy{
			Exchange: resource.ExchangePolicy{AllowedClientIDs: allowedClientIDs},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.stores.resources.Create(context.Background(), r); err != nil {
		t.Fatalf("seed mint resource %q: %v", slug, err)
	}
	return r
}

// seedBrokerProvider creates a BrokerProvider row.
func (s *dispatchSetup) seedBrokerProvider(t *testing.T, slug string) *resource.BrokerProvider {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	p := &resource.BrokerProvider{
		ID:          "p-" + slug,
		Slug:        slug,
		DisplayName: "Provider " + slug,
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"client_id":"x"}`),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.stores.providers.Create(context.Background(), p); err != nil {
		t.Fatalf("seed broker provider %q: %v", slug, err)
	}
	return p
}

// seedBrokerResource creates a broker Resource pointing at the given
// provider. Each scope ships with an upstream alias (
// mapping precondition).
func (s *dispatchSetup) seedBrokerResource(t *testing.T, slug string, providerID string, scopes []string, allowedClientIDs []string) *resource.Resource {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	scs := make([]resource.Scope, len(scopes))
	for i, name := range scopes {
		scs[i] = resource.Scope{Name: name, Upstream: name}
	}
	r := &resource.Resource{
		ID:               "res-" + slug,
		Slug:             slug,
		DisplayName:      "Broker " + slug,
		URI:              "https://" + slug + ".upstream.example.com",
		BackendKind:      resource.BackendBroker,
		BrokerProviderID: providerID,
		Scopes:           scs,
		Policy: resource.Policy{
			Exchange: resource.ExchangePolicy{AllowedClientIDs: allowedClientIDs},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.stores.resources.Create(context.Background(), r); err != nil {
		t.Fatalf("seed broker resource %q: %v", slug, err)
	}
	return r
}

// seedUser inserts a minimal user row so consent_grants FK is
// satisfiable.
func (s *dispatchSetup) seedUser(t *testing.T, id string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	u := &user.User{
		ID: id, Email: id + "@example.com", Name: "User " + id,
		PasswordHash: "$2a$10$fakehash", Role: user.RoleUser,
		Status: user.StatusActive, Provider: user.ProviderLocal,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.h.Stores.User.Create(context.Background(), u); err != nil {
		t.Fatalf("seed user %q: %v", id, err)
	}
}

func (s *dispatchSetup) seedConsentGrant(t *testing.T, userID, clientID, resourceID string, scopes []string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	g := &resource.ConsentGrant{
		ID:         "cg-" + userID + "-" + clientID + "-" + resourceID,
		UserID:     userID,
		ClientID:   clientID,
		ResourceID: resourceID,
		Scopes:     scopes,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := s.stores.consents.Upsert(context.Background(), g); err != nil {
		t.Fatalf("seed consent grant: %v", err)
	}
}

func (s *dispatchSetup) seedBrokerGrant(t *testing.T, userID, providerID string, upstreamScopes []string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	owner := "broker:" + userID + ":" + providerID
	g := &resource.BrokerGrant{
		ID:               "bg-" + userID + "-" + providerID,
		UserID:           userID,
		BrokerProviderID: providerID,
		CredentialData:   []byte("enc:" + owner + ":live-token"),
		ScopesGranted:    upstreamScopes,
		EncBackend:       "dispatch-test",
		Version:          1,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := s.stores.brokerGrants.Create(context.Background(), g); err != nil {
		t.Fatalf("seed broker grant: %v", err)
	}
}

// dispatchEncryptor mirrors the broker_issuer test fake so the unified
// dispatch tests can decrypt the seeded credentialData. Pure pass-through
// over the "enc:<owner>:" prefix; tests asserting on the plaintext expect
// "live-token".
type dispatchEncryptor struct{}

func (e *dispatchEncryptor) Encrypt(_ context.Context, plaintext []byte, ownerContext string) ([]byte, error) {
	return append([]byte("enc:"+ownerContext+":"), plaintext...), nil
}

func (e *dispatchEncryptor) Decrypt(_ context.Context, ciphertext []byte, ownerContext string) ([]byte, error) {
	prefix := []byte("enc:" + ownerContext + ":")
	if len(ciphertext) >= len(prefix) && string(ciphertext[:len(prefix)]) == string(prefix) {
		return ciphertext[len(prefix):], nil
	}
	return ciphertext, nil
}

func (e *dispatchEncryptor) DriverName() string { return "dispatch-test" }

// dispatchStubAdapter is a brokerproto.BrokerProtocol stub that returns a
// deterministic upstream token and records the credential it saw, so
// tests can assert dispatch reached the adapter.
type dispatchStubAdapter struct {
	name string

	mu         sync.Mutex
	vendCalls  int
	lastCred   []byte
	lastScopes []string
}

func (s *dispatchStubAdapter) Name() string { return s.name }

func (s *dispatchStubAdapter) BuildConnectURL(
	context.Context, *resource.BrokerProvider, *resource.Resource,
	string, string, string, []string,
) (string, *resource.ConnectPendingState, error) {
	return "", nil, nil
}

func (s *dispatchStubAdapter) HandleCallback(
	context.Context, *resource.BrokerProvider, *resource.Resource,
	string, string, *resource.ConnectPendingState,
) ([]byte, []string, error) {
	return nil, nil, nil
}

func (s *dispatchStubAdapter) Vend(
	_ context.Context,
	_ *resource.BrokerProvider,
	r *resource.Resource,
	credential []byte,
	scopes []string,
) (string, int, []byte, error) {
	s.mu.Lock()
	s.vendCalls++
	s.lastCred = append([]byte(nil), credential...)
	s.lastScopes = append([]string(nil), scopes...)
	s.mu.Unlock()
	return "upstream-tok-" + r.Slug, 3600, nil, nil
}

func (s *dispatchStubAdapter) Revoke(context.Context, *resource.BrokerProvider, []byte) error {
	return nil
}

// createClientWithID creates a confidential client with a deterministic
// id (lowercase, hyphenated) so the same string can double as a
// resources.slug. The slug regex (^[a-z0-9][a-z0-9-]{0,63}$) rejects
// the upper-case characters that crypto.GenerateClientID produces, so
// the random helper is unsafe for tests that pin the actor MCP's
// resource row to its client_id.
func (s *dispatchSetup) createClientWithID(t *testing.T, id string, isAgent bool) (*client.Client, string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	secret := "test-secret-" + id
	hash, err := crypto.HashBcrypt(secret)
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}

	c := &client.Client{
		ID:                      id,
		SecretHash:              hash,
		Name:                    "Dispatch Test Client " + id,
		RedirectURIs:            []string{},
		GrantTypes:              []string{token.GrantTypeTokenExchange},
		ResponseTypes:           []string{},
		TokenEndpointAuthMethod: "client_secret_basic",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceAdmin,
		IsAgent:                 isAgent,
		IssuedAt:                now,
		UpdatedAt:               now,
	}
	if err := s.h.Stores.Client.Create(ctx, c); err != nil {
		t.Fatalf("create client %q: %v", id, err)
	}
	return c, secret
}

// makeAgentClient creates an agent client whose id is a slug-shaped
// constant. The "agent" name is the convention every dispatch test in
// this file uses for the subject token's issuing client.
func (s *dispatchSetup) makeAgentClient(t *testing.T, slug string) (*client.Client, string) {
	t.Helper()
	return s.createClientWithID(t, "agent-"+slug, true)
}

// makeActorClient creates a slug-shaped MCP client. When pinResource is
// true the same ID is also seeded as a Mint resource so the broker
// agent-attestation gate's registry.Resolve(client_id) succeeds.
func (s *dispatchSetup) makeActorClient(t *testing.T, slug string) (*client.Client, string) {
	t.Helper()
	return s.createClientWithID(t, "actor-"+slug, false)
}

// -------------------------------------------------------------------
// 1. Mint dispatch — happy path
// -------------------------------------------------------------------

func TestTokenExchangeService_Dispatch_MintTarget_HappyPath(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	agent, _ := setup.makeAgentClient(t, "agent")
	actor, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "")

	mintRes := setup.seedMintResource(t, "tasks-mcp", []string{"tasks.read", "tasks.write"}, nil)
	setup.seedUser(t, "user-alice")
	setup.seedConsentGrant(t, "user-alice", agent.ID, mintRes.ID, []string{"tasks.read", "tasks.write"})

	subjectClaims := identitySubjectClaims(agent.ID)
	subjectClaims.Subject = "user-alice"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	resp, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actor.ID,
		ClientSecret:     actorSecret,
		Resource:         "tasks-mcp",
		Scope:            "tasks.read",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("expected non-empty access_token")
	}
	if resp.IssuedTokenType != token.TokenTypeAccessToken {
		t.Errorf("issued_token_type = %q, want %q", resp.IssuedTokenType, token.TokenTypeAccessToken)
	}
	if resp.Scope != "tasks.read" {
		t.Errorf("scope = %q, want tasks.read", resp.Scope)
	}

	claims := parseClaims(t, resp.AccessToken)
	if claims["sub"] != "user-alice" {
		t.Errorf("sub = %v, want user-alice", claims["sub"])
	}
	auds, _ := claims["aud"].([]any)
	if len(auds) != 1 || auds[0] != mintRes.URI {
		t.Errorf("aud = %v, want [%s]", claims["aud"], mintRes.URI)
	}
	if claims["scope"] != "tasks.read" {
		t.Errorf("scope claim = %v, want tasks.read", claims["scope"])
	}
}

// -------------------------------------------------------------------
// 2. Mint dispatch — no consent grant → ConsentRequired
// -------------------------------------------------------------------

func TestTokenExchangeService_Dispatch_MintTarget_NoConsent_Required(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	agent, _ := setup.makeAgentClient(t, "agent")
	actor, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "")
	mintRes := setup.seedMintResource(t, "secrets-mcp", []string{"secrets.read"}, nil)
	setup.seedUser(t, "user-bob")
	// Deliberately NO consent_grant for (user-bob, agent, secrets-mcp).
	_ = mintRes

	subjectClaims := identitySubjectClaims(agent.ID)
	subjectClaims.Subject = "user-bob"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actor.ID,
		ClientSecret:     actorSecret,
		Resource:         "secrets-mcp",
		Scope:            "secrets.read",
	})
	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("expected *domain.ConsentRequiredError, got %v", err)
	}
	if cre.ResourceSlug != "secrets-mcp" {
		t.Errorf("ResourceSlug = %q, want secrets-mcp", cre.ResourceSlug)
	}
	if cre.Service != "secrets-mcp" {
		t.Errorf("Service (legacy) = %q, want secrets-mcp", cre.Service)
	}
	// : Cause is populated for symmetry with the bound-3 broker path.
	if cre.Cause != domain.CauseConsentMissing {
		t.Errorf("Cause = %q, want %q", cre.Cause, domain.CauseConsentMissing)
	}
	if len(cre.MissingScopes) != 0 {
		t.Errorf("MissingScopes = %v, want nil (no grant → no scope diagnostic)", cre.MissingScopes)
	}
}

// -------------------------------------------------------------------
// 3. Mint dispatch — requested scope outside consented set
// -------------------------------------------------------------------

func TestTokenExchangeService_Dispatch_MintTarget_ScopeNotConsented_Required(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	agent, _ := setup.makeAgentClient(t, "agent")
	actor, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "")
	mintRes := setup.seedMintResource(t, "files-mcp", []string{"files.read", "files.write"}, nil)
	setup.seedUser(t, "user-carol")
	// Consent only covers files.read; the request asks for files.write too.
	setup.seedConsentGrant(t, "user-carol", agent.ID, mintRes.ID, []string{"files.read"})

	subjectClaims := identitySubjectClaims(agent.ID)
	subjectClaims.Subject = "user-carol"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actor.ID,
		ClientSecret:     actorSecret,
		Resource:         "files-mcp",
		Scope:            "files.read files.write",
	})
	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("expected *domain.ConsentRequiredError, got %v", err)
	}
	// : scope-coverage failure populates Cause + the missing list.
	// Order is preserved from req.Scope's strings.Fields output, so
	// "files.write" comes back since "files.read" was consented.
	if cre.Cause != domain.CauseScopeInsufficient {
		t.Errorf("Cause = %q, want %q", cre.Cause, domain.CauseScopeInsufficient)
	}
	wantMissing := []string{"files.write"}
	if len(cre.MissingScopes) != 1 || cre.MissingScopes[0] != wantMissing[0] {
		t.Errorf("MissingScopes = %v, want %v", cre.MissingScopes, wantMissing)
	}
}

// -------------------------------------------------------------------
// 4. Mint dispatch — operator gate empty allowlist allows any client
// -------------------------------------------------------------------

func TestTokenExchangeService_Dispatch_MintTarget_OperatorGate_Empty_AllowsAny(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	agent, _ := setup.makeAgentClient(t, "agent")
	actor, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "")
	mintRes := setup.seedMintResource(t, "open-mcp", []string{"open.read"}, nil) // empty allowlist
	setup.seedUser(t, "user-dave")
	setup.seedConsentGrant(t, "user-dave", agent.ID, mintRes.ID, []string{"open.read"})

	subjectClaims := identitySubjectClaims(agent.ID)
	subjectClaims.Subject = "user-dave"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	resp, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actor.ID,
		ClientSecret:     actorSecret,
		Resource:         "open-mcp",
		Scope:            "open.read",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("expected non-empty access_token")
	}
}

// -------------------------------------------------------------------
// 5. Mint dispatch — operator gate non-empty allowlist rejects
// non-allowed actor
// -------------------------------------------------------------------

func TestTokenExchangeService_Dispatch_MintTarget_OperatorGate_NonEmpty_RejectsNonAllowed(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	agent, _ := setup.makeAgentClient(t, "agent")
	allowed, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "")
	rejected, rejectedSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "")
	mintRes := setup.seedMintResource(t, "strict-mcp", []string{"strict.read"}, []string{allowed.ID})
	setup.seedUser(t, "user-eve")
	setup.seedConsentGrant(t, "user-eve", agent.ID, mintRes.ID, []string{"strict.read"})

	subjectClaims := identitySubjectClaims(agent.ID)
	subjectClaims.Subject = "user-eve"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         rejected.ID,
		ClientSecret:     rejectedSecret,
		Resource:         "strict-mcp",
		Scope:            "strict.read",
	})
	if !errors.Is(err, domain.ErrTokenExchangeNotAuthorized) {
		t.Fatalf("expected ErrTokenExchangeNotAuthorized, got %v", err)
	}
}

// -------------------------------------------------------------------
// 6. Broker dispatch — happy path
// -------------------------------------------------------------------

func TestTokenExchangeService_Dispatch_BrokerTarget_HappyPath(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	agent, _ := setup.makeAgentClient(t, "broker-happy")
	// Actor MCP — its client_id matches its mint resource slug, so the
	// agent-attestation gate can resolve "<actor.ID>" to a Mint resource.
	actor, actorSecret := setup.makeActorClient(t, "broker-happy")
	actorMintRes := setup.seedMintResource(t, actor.ID, []string{"actor.act"}, nil)
	provider := setup.seedBrokerProvider(t, "github")
	brokerRes := setup.seedBrokerResource(t, "github-cal", provider.ID, []string{"repo"}, nil)

	setup.seedUser(t, "user-frank")
	// Agent-attestation grant: (user, agent, actor-as-mcp). 's
	// bound-C requires the attestation to cover the requested broker
	// scope, so include "repo" alongside the actor MCP's own scope.
	setup.seedConsentGrant(t, "user-frank", agent.ID, actorMintRes.ID, []string{"actor.act", "repo"})
	// Broker grant for upstream provider.
	setup.seedBrokerGrant(t, "user-frank", provider.ID, []string{"repo"})

	subjectClaims := identitySubjectClaims(agent.ID)
	subjectClaims.Subject = "user-frank"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	resp, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actor.ID,
		ClientSecret:     actorSecret,
		Resource:         "github-cal",
		Scope:            "repo",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.AccessToken != "upstream-tok-"+brokerRes.Slug {
		t.Errorf("AccessToken = %q, want upstream-tok-%s", resp.AccessToken, brokerRes.Slug)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want Bearer", resp.TokenType)
	}
	setup.brokerStub.mu.Lock()
	calls := setup.brokerStub.vendCalls
	cred := string(setup.brokerStub.lastCred)
	setup.brokerStub.mu.Unlock()
	if calls != 1 {
		t.Errorf("brokerStub.vendCalls = %d, want 1", calls)
	}
	if cred != "live-token" {
		t.Errorf("brokerStub.lastCred = %q, want live-token (decrypted)", cred)
	}
}

// -------------------------------------------------------------------
// 7. Broker dispatch — operator gate rejects
// -------------------------------------------------------------------

func TestTokenExchangeService_Dispatch_BrokerTarget_OperatorGateFails_Rejected(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	agent, _ := setup.makeAgentClient(t, "agent")
	allowed, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "")
	rejected, rejectedSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "")
	provider := setup.seedBrokerProvider(t, "linear")
	setup.seedBrokerResource(t, "linear-resource", provider.ID, []string{"issues.read"}, []string{allowed.ID})

	setup.seedUser(t, "user-grace")
	setup.seedBrokerGrant(t, "user-grace", provider.ID, []string{"issues.read"})

	subjectClaims := identitySubjectClaims(agent.ID)
	subjectClaims.Subject = "user-grace"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         rejected.ID,
		ClientSecret:     rejectedSecret,
		Resource:         "linear-resource",
		Scope:            "issues.read",
	})
	if !errors.Is(err, domain.ErrTokenExchangeNotAuthorized) {
		t.Fatalf("expected ErrTokenExchangeNotAuthorized, got %v", err)
	}
}

// -------------------------------------------------------------------
// 8. Broker dispatch — agent-attestation grant missing
// -------------------------------------------------------------------

func TestTokenExchangeService_Dispatch_BrokerTarget_AgentAttestationFails_ConsentRequired(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	agent, _ := setup.makeAgentClient(t, "broker-att-fail")
	actor, actorSecret := setup.makeActorClient(t, "broker-att-fail")
	// Actor IS registered as a Mint resource…
	actorMintRes := setup.seedMintResource(t, actor.ID, []string{"actor.act"}, nil)
	_ = actorMintRes
	provider := setup.seedBrokerProvider(t, "slack")
	setup.seedBrokerResource(t, "slack-bot", provider.ID, []string{"chat.write"}, nil)

	setup.seedUser(t, "user-heidi")
	// …but NO consent_grant for (user-heidi, agent, actor-as-mcp).
	setup.seedBrokerGrant(t, "user-heidi", provider.ID, []string{"chat.write"})

	subjectClaims := identitySubjectClaims(agent.ID)
	subjectClaims.Subject = "user-heidi"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actor.ID,
		ClientSecret:     actorSecret,
		Resource:         "slack-bot",
		Scope:            "chat.write",
	})
	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("expected *domain.ConsentRequiredError, got %v", err)
	}
	// Agent-attestation failure points at the actor MCP, not the broker.
	if cre.ResourceSlug != actor.ID {
		t.Errorf("ResourceSlug = %q, want actor MCP slug %q", cre.ResourceSlug, actor.ID)
	}
	// : bound-B failure (no agent-attestation row) carries
	// CauseConsentMissing; ProviderSlug stays empty so the handler picks
	// the AS-side re-consent URL flavor.
	if cre.Cause != domain.CauseConsentMissing {
		t.Errorf("Cause = %q, want %q", cre.Cause, domain.CauseConsentMissing)
	}
	if cre.ProviderSlug != "" {
		t.Errorf("ProviderSlug = %q, want empty (bound-B keys on actor MCP)", cre.ProviderSlug)
	}
	if len(cre.MissingScopes) != 0 {
		t.Errorf("MissingScopes = %v, want nil (no grant → no scope diagnostic)", cre.MissingScopes)
	}
}

// -------------------------------------------------------------------
// 9. Broker dispatch — no broker_grant → ConsentRequired with
// ProviderSlug + ResourceSlug populated
// -------------------------------------------------------------------

func TestTokenExchangeService_Dispatch_BrokerTarget_NoBrokerGrant_ConsentRequired_WithConnectURL(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	agent, _ := setup.makeAgentClient(t, "broker-no-bg")
	actor, actorSecret := setup.makeActorClient(t, "broker-no-bg")
	actorMintRes := setup.seedMintResource(t, actor.ID, []string{"actor.act"}, nil)
	provider := setup.seedBrokerProvider(t, "notion")
	brokerRes := setup.seedBrokerResource(t, "notion-pages", provider.ID, []string{"pages.read"}, nil)

	setup.seedUser(t, "user-ivan")
	// Agent-attestation grant present, broker_grant absent. 's
	// bound-C requires the attestation to cover the requested broker
	// scope, so include "pages.read" alongside the actor MCP's own scope.
	setup.seedConsentGrant(t, "user-ivan", agent.ID, actorMintRes.ID, []string{"actor.act", "pages.read"})

	subjectClaims := identitySubjectClaims(agent.ID)
	subjectClaims.Subject = "user-ivan"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actor.ID,
		ClientSecret:     actorSecret,
		Resource:         "notion-pages",
		Scope:            "pages.read",
	})
	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("expected *domain.ConsentRequiredError, got %v", err)
	}
	if cre.ProviderSlug != provider.Slug {
		t.Errorf("ProviderSlug = %q, want %q", cre.ProviderSlug, provider.Slug)
	}
	if cre.ResourceSlug != brokerRes.Slug {
		t.Errorf("ResourceSlug = %q, want %q", cre.ResourceSlug, brokerRes.Slug)
	}
	if cre.Service != provider.Slug {
		t.Errorf("Service (legacy fallback) = %q, want %q", cre.Service, provider.Slug)
	}
	// : the wrapper preserves the bound-D Cause from BrokerIssuer.
	if cre.Cause != domain.CauseConsentMissing {
		t.Errorf("Cause = %q, want %q (bound-D wrapped)", cre.Cause, domain.CauseConsentMissing)
	}
}

// -------------------------------------------------------------------
// 10. Scope not in resource catalog → invalid_scope
// -------------------------------------------------------------------

func TestTokenExchangeService_Dispatch_ScopeNotInCatalog_Rejected(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	agent, _ := setup.makeAgentClient(t, "agent")
	actor, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "")
	mintRes := setup.seedMintResource(t, "narrow-mcp", []string{"narrow.read"}, nil)
	setup.seedUser(t, "user-judy")
	setup.seedConsentGrant(t, "user-judy", agent.ID, mintRes.ID, []string{"narrow.read"})

	subjectClaims := identitySubjectClaims(agent.ID)
	subjectClaims.Subject = "user-judy"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actor.ID,
		ClientSecret:     actorSecret,
		Resource:         "narrow-mcp",
		Scope:            "narrow.write", // not in the catalog
	})
	if !errors.Is(err, domain.ErrScopeNotInCatalog) {
		t.Fatalf("expected ErrScopeNotInCatalog, got %v", err)
	}
}

// -------------------------------------------------------------------
// 11. Registry resolves more than one row → ErrAmbiguousResource
// -------------------------------------------------------------------

func TestTokenExchangeService_Dispatch_RegistryResolveAmbiguous_Error(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	// Two resources sharing the same URI — Resolve('shared-uri') matches both.
	now := time.Now().UTC().Truncate(time.Second)
	mk := func(slug string) *resource.Resource {
		return &resource.Resource{
			ID:          "res-" + slug,
			Slug:        slug,
			DisplayName: "amb " + slug,
			URI:         "https://shared.example.com",
			BackendKind: resource.BackendMint,
			Scopes:      []resource.Scope{{Name: "x.read"}},
			CreatedAt:   now,
			UpdatedAt:   now,
		}
	}
	for _, slug := range []string{"amb-one", "amb-two"} {
		if err := setup.stores.resources.Create(ctx, mk(slug)); err != nil {
			t.Fatalf("seed %s: %v", slug, err)
		}
	}

	agent, _ := setup.makeAgentClient(t, "agent")
	actor, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "")
	subjectClaims := identitySubjectClaims(agent.ID)
	subjectClaims.Subject = "user-kate"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actor.ID,
		ClientSecret:     actorSecret,
		Resource:         "https://shared.example.com",
		Scope:            "x.read",
	})
	if !errors.Is(err, domain.ErrAmbiguousResource) {
		t.Fatalf("expected ErrAmbiguousResource, got %v", err)
	}
}

// -------------------------------------------------------------------
// 12. Registry-or-bust: unknown resource returns ErrResourceNotFound (no
// legacy fall-through after  retired the inline mint path).
// -------------------------------------------------------------------

func TestTokenExchangeService_UnknownResource_ReturnsResourceNotFound(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	subClient, subSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	subjectClaims := defaultSubjectClaims(subClient.ID)
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         subClient.ID,
		ClientSecret:     subSecret,
		Resource:         "https://unknown.example.com",
		Scope:            "read",
	})
	if !errors.Is(err, domain.ErrResourceNotFound) {
		t.Fatalf("Exchange with unknown resource: got %v, want ErrResourceNotFound", err)
	}
}

// (Legacy upstream-connection-vend dispatch test deleted in  along
// with isConnectionResource / handleConnectionVend; the only fall-through
// from the unified registry today is the inline mint flow exercised by
// TestTokenExchangeService_LegacyPath_StillWorks_WhenRegistryReturnsNotFound
// above.)

// -------------------------------------------------------------------
//  — bound-C: agent-attestation scope coverage on
// dispatchBroker. The seed sets attestation.Scopes to a strict subset of
// the requested scope; the test asserts a ConsentRequiredError keyed on
// the actor MCP slug with Cause=CauseScopeInsufficient.
//
// Load-bearing unit-test regression. Without this test, a future
// refactor could re-introduce the gap — e.g., by moving the scope-coverage
// check into BrokerIssuer.Issue, where it would still fire AFTER the
// upstream call has happened in some imagined future code path.
// -------------------------------------------------------------------

func TestDispatchBroker_BoundC_ScopeNotConsented_PopulatesCauseScopeInsufficient(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	agent, _ := setup.makeAgentClient(t, "broker-bc-fail")
	actor, actorSecret := setup.makeActorClient(t, "broker-bc-fail")
	actorMintRes := setup.seedMintResource(t, actor.ID, []string{"actor.act"}, nil)
	provider := setup.seedBrokerProvider(t, "github-bc")
	setup.seedBrokerResource(t, "github-repo-bc", provider.ID, []string{"repo", "admin:org"}, nil)

	setup.seedUser(t, "user-bc")
	// Attestation only covers "repo" — request includes "admin:org".
	setup.seedConsentGrant(t, "user-bc", agent.ID, actorMintRes.ID, []string{"repo"})
	setup.seedBrokerGrant(t, "user-bc", provider.ID, []string{"repo", "admin:org"})

	subjectClaims := identitySubjectClaims(agent.ID)
	subjectClaims.Subject = "user-bc"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actor.ID,
		ClientSecret:     actorSecret,
		Resource:         "github-repo-bc",
		Scope:            "admin:org",
	})
	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("expected *domain.ConsentRequiredError, got %v", err)
	}
	if cre.Cause != domain.CauseScopeInsufficient {
		t.Errorf("Cause = %q, want %q", cre.Cause, domain.CauseScopeInsufficient)
	}
	wantMissing := []string{"admin:org"}
	if len(cre.MissingScopes) != 1 || cre.MissingScopes[0] != wantMissing[0] {
		t.Errorf("MissingScopes = %v, want %v", cre.MissingScopes, wantMissing)
	}
	if cre.ResourceSlug != actor.ID {
		t.Errorf("ResourceSlug = %q, want actor MCP slug %q (bound-C re-consents at AS, not upstream)", cre.ResourceSlug, actor.ID)
	}
	if cre.ProviderSlug != "" {
		t.Errorf("ProviderSlug = %q, want empty (bound-C keys on actor MCP)", cre.ProviderSlug)
	}
}

func TestDispatchBroker_BoundC_PartialOverlap_OnlyMissingReported(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	agent, _ := setup.makeAgentClient(t, "broker-bc-partial")
	actor, actorSecret := setup.makeActorClient(t, "broker-bc-partial")
	actorMintRes := setup.seedMintResource(t, actor.ID, []string{"actor.act"}, nil)
	provider := setup.seedBrokerProvider(t, "github-partial")
	setup.seedBrokerResource(t, "github-repo-partial", provider.ID, []string{"repo", "admin:org"}, nil)

	setup.seedUser(t, "user-bc-partial")
	// Attestation covers "repo" only; request includes both.
	setup.seedConsentGrant(t, "user-bc-partial", agent.ID, actorMintRes.ID, []string{"repo"})
	setup.seedBrokerGrant(t, "user-bc-partial", provider.ID, []string{"repo", "admin:org"})

	subjectClaims := identitySubjectClaims(agent.ID)
	subjectClaims.Subject = "user-bc-partial"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actor.ID,
		ClientSecret:     actorSecret,
		Resource:         "github-repo-partial",
		Scope:            "repo admin:org",
	})
	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("expected *domain.ConsentRequiredError, got %v", err)
	}
	wantMissing := []string{"admin:org"}
	if len(cre.MissingScopes) != 1 || cre.MissingScopes[0] != wantMissing[0] {
		t.Errorf("MissingScopes = %v, want %v (order preserved from req.Scope)", cre.MissingScopes, wantMissing)
	}
}

func TestDispatchBroker_BoundC_EmptyAttestationScopes_RejectsAllRequested(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	agent, _ := setup.makeAgentClient(t, "broker-bc-empty")
	actor, actorSecret := setup.makeActorClient(t, "broker-bc-empty")
	actorMintRes := setup.seedMintResource(t, actor.ID, []string{"actor.act"}, nil)
	provider := setup.seedBrokerProvider(t, "github-empty")
	setup.seedBrokerResource(t, "github-repo-empty", provider.ID, []string{"repo"}, nil)

	setup.seedUser(t, "user-bc-empty")
	// Attestation with empty Scopes covers nothing, even though the row
	// exists. dispatchMint's grant.CoversScopes uses the same convention.
	setup.seedConsentGrant(t, "user-bc-empty", agent.ID, actorMintRes.ID, []string{})
	setup.seedBrokerGrant(t, "user-bc-empty", provider.ID, []string{"repo"})

	subjectClaims := identitySubjectClaims(agent.ID)
	subjectClaims.Subject = "user-bc-empty"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actor.ID,
		ClientSecret:     actorSecret,
		Resource:         "github-repo-empty",
		Scope:            "repo",
	})
	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("expected *domain.ConsentRequiredError, got %v", err)
	}
	if cre.Cause != domain.CauseScopeInsufficient {
		t.Errorf("Cause = %q, want %q", cre.Cause, domain.CauseScopeInsufficient)
	}
	wantMissing := []string{"repo"}
	if len(cre.MissingScopes) != 1 || cre.MissingScopes[0] != wantMissing[0] {
		t.Errorf("MissingScopes = %v, want %v", cre.MissingScopes, wantMissing)
	}
}

func TestDispatchBroker_BoundC_ExactMatch_PassesToBrokerIssuer(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	agent, _ := setup.makeAgentClient(t, "broker-bc-exact")
	actor, actorSecret := setup.makeActorClient(t, "broker-bc-exact")
	actorMintRes := setup.seedMintResource(t, actor.ID, []string{"actor.act"}, nil)
	provider := setup.seedBrokerProvider(t, "github-exact")
	brokerRes := setup.seedBrokerResource(t, "github-repo-exact", provider.ID, []string{"repo"}, nil)

	setup.seedUser(t, "user-bc-exact")
	// Attestation matches the requested scope exactly. Bound C passes;
	// dispatchBroker reaches BrokerIssuer.Issue and the test asserts the
	// vend went through.
	setup.seedConsentGrant(t, "user-bc-exact", agent.ID, actorMintRes.ID, []string{"repo"})
	setup.seedBrokerGrant(t, "user-bc-exact", provider.ID, []string{"repo"})

	subjectClaims := identitySubjectClaims(agent.ID)
	subjectClaims.Subject = "user-bc-exact"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	resp, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actor.ID,
		ClientSecret:     actorSecret,
		Resource:         "github-repo-exact",
		Scope:            "repo",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.AccessToken != "upstream-tok-"+brokerRes.Slug {
		t.Errorf("AccessToken = %q, want upstream-tok-%s", resp.AccessToken, brokerRes.Slug)
	}
}

// TestDispatchBroker_BoundC_FailsBeforeBrokerIssuerIsCalled is the
// short-circuit invariant. Bound C must fail BEFORE BrokerIssuer.Issue
// touches the upstream — so even if a future refactor moves the
// scope-coverage check into BrokerIssuer, the dispatch-side gate must
// still fire first. The signal is the broker stub adapter's vend-call
// counter: a bound-C failure must leave it at zero.
func TestDispatchBroker_BoundC_FailsBeforeBrokerIssuerIsCalled(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	agent, _ := setup.makeAgentClient(t, "broker-bc-shortc")
	actor, actorSecret := setup.makeActorClient(t, "broker-bc-shortc")
	actorMintRes := setup.seedMintResource(t, actor.ID, []string{"actor.act"}, nil)
	provider := setup.seedBrokerProvider(t, "github-shortc")
	setup.seedBrokerResource(t, "github-repo-shortc", provider.ID, []string{"repo", "admin:org"}, nil)

	setup.seedUser(t, "user-bc-shortc")
	setup.seedConsentGrant(t, "user-bc-shortc", agent.ID, actorMintRes.ID, []string{"repo"})
	setup.seedBrokerGrant(t, "user-bc-shortc", provider.ID, []string{"repo", "admin:org"})

	subjectClaims := identitySubjectClaims(agent.ID)
	subjectClaims.Subject = "user-bc-shortc"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actor.ID,
		ClientSecret:     actorSecret,
		Resource:         "github-repo-shortc",
		Scope:            "admin:org",
	})
	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("expected *domain.ConsentRequiredError, got %v", err)
	}
	setup.brokerStub.mu.Lock()
	calls := setup.brokerStub.vendCalls
	setup.brokerStub.mu.Unlock()
	if calls != 0 {
		t.Errorf("brokerStub.vendCalls = %d, want 0 (bound-C must short-circuit before adapter.Vend)", calls)
	}
}

// TestDispatchBroker_BoundE_ScopeInsufficient_WrappedErrorPreservesCauseAndMissingScopes
// covers the wrapper at the dispatch layer: when BrokerIssuer.Issue
// returns a ConsentRequiredError with Cause=CauseScopeInsufficient (bound
// E — the broker_grants ceiling rejected the upstream form), the wrapper
// preserves Cause and MissingScopes while adding the typed slug fields.
func TestDispatchBroker_BoundE_ScopeInsufficient_WrappedErrorPreservesCauseAndMissingScopes(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	agent, _ := setup.makeAgentClient(t, "broker-be-wrap")
	actor, actorSecret := setup.makeActorClient(t, "broker-be-wrap")
	actorMintRes := setup.seedMintResource(t, actor.ID, []string{"actor.act"}, nil)
	provider := setup.seedBrokerProvider(t, "github-wrap")
	brokerRes := setup.seedBrokerResource(t, "github-repo-wrap", provider.ID, []string{"repo"}, nil)

	setup.seedUser(t, "user-be-wrap")
	// Bound C passes (attestation covers "repo"); but the broker_grant
	// does NOT cover "repo" upstream-form → bound E fires inside
	// BrokerIssuer.Issue; the dispatch-side wrapper must preserve Cause +
	// MissingScopes.
	setup.seedConsentGrant(t, "user-be-wrap", agent.ID, actorMintRes.ID, []string{"repo"})
	setup.seedBrokerGrant(t, "user-be-wrap", provider.ID, []string{"some-other-scope"})

	subjectClaims := identitySubjectClaims(agent.ID)
	subjectClaims.Subject = "user-be-wrap"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actor.ID,
		ClientSecret:     actorSecret,
		Resource:         "github-repo-wrap",
		Scope:            "repo",
	})
	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("expected *domain.ConsentRequiredError, got %v", err)
	}
	if cre.Cause != domain.CauseScopeInsufficient {
		t.Errorf("Cause = %q, want %q (bound-E wrapped)", cre.Cause, domain.CauseScopeInsufficient)
	}
	if len(cre.MissingScopes) == 0 {
		t.Errorf("MissingScopes empty, want upstream-form list preserved through wrapper")
	}
	if cre.ProviderSlug != provider.Slug {
		t.Errorf("ProviderSlug = %q, want %q (wrapper sets it)", cre.ProviderSlug, provider.Slug)
	}
	if cre.ResourceSlug != brokerRes.Slug {
		t.Errorf("ResourceSlug = %q, want %q (wrapper sets it)", cre.ResourceSlug, brokerRes.Slug)
	}
}

// -------------------------------------------------------------------
// Self-exchange (Mint dispatch): with allow_self_exchange on and the
// requesting client == the subject token's client_id, consent is skipped.
// The operator gate ran first and, with the empty allowlist seeded here,
// restricts nothing — the first test pins that composed default on purpose.
// -------------------------------------------------------------------

func TestTokenExchangeService_Dispatch_MintTarget_SelfExchange_UserSubject_AllowsWithoutConsent(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	self, selfSecret := setup.createClientWithID(t, "self-mint-agent", true)
	mintRes := setup.seedMintResource(t, "tasks-mcp", []string{"tasks.read", "tasks.write"}, nil)
	setup.seedUser(t, "user-dave")
	// Deliberately NO consent grant for (user-dave, self, tasks-mcp).

	subjectClaims := identitySubjectClaims(self.ID)
	subjectClaims.Subject = "user-dave"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	resp, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         self.ID,
		ClientSecret:     selfSecret,
		Resource:         "tasks-mcp",
		Scope:            "tasks.read",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("expected non-empty access_token")
	}
	if resp.Scope != "tasks.read" {
		t.Errorf("scope = %q, want tasks.read", resp.Scope)
	}
	claims := parseClaims(t, resp.AccessToken)
	if claims["client_id"] != self.ID {
		t.Errorf("client_id = %v, want %q", claims["client_id"], self.ID)
	}
	if claims["sub"] != "user-dave" {
		t.Errorf("sub = %v, want user-dave", claims["sub"])
	}
	auds, _ := claims["aud"].([]any)
	if len(auds) != 1 || auds[0] != mintRes.URI {
		t.Errorf("aud = %v, want [%s]", claims["aud"], mintRes.URI)
	}
}

// CC subject: sub == client_id, consent_grants is keyed on user_id and
// can never have a matching row, so the self-exchange branch is the
// only one that can authorize.
func TestTokenExchangeService_Dispatch_MintTarget_SelfExchange_ClientCredentialsSubject(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	self, selfSecret := setup.createClientWithID(t, "calc-mcp-demo", false)
	mintRes := setup.seedMintResource(t, "calculator-mcp-demo", []string{"tools/add", "tools/multiply"}, nil)
	// No user row, no consent grant. CC subject's sub == its own client_id.

	subjectClaims := defaultSubjectClaims(self.ID)
	subjectClaims.Subject = self.ID
	subjectClaims.Scope = "tools/add tools/multiply"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	resp, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         self.ID,
		ClientSecret:     selfSecret,
		Resource:         "calculator-mcp-demo",
		Scope:            "tools/add",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("expected non-empty access_token")
	}
	if resp.Scope != "tools/add" {
		t.Errorf("scope = %q, want tools/add", resp.Scope)
	}
	claims := parseClaims(t, resp.AccessToken)
	if claims["sub"] != self.ID {
		t.Errorf("sub = %v, want %q (CC subject)", claims["sub"], self.ID)
	}
	if claims["client_id"] != self.ID {
		t.Errorf("client_id = %v, want %q", claims["client_id"], self.ID)
	}
	auds, _ := claims["aud"].([]any)
	if len(auds) != 1 || auds[0] != mintRes.URI {
		t.Errorf("aud = %v, want [%s]", claims["aud"], mintRes.URI)
	}
}

// Inverse invariant: with AllowSelfExchange off, the consent gate
// applies even when req.ClientID matches the subject's client_id.
func TestTokenExchangeService_Dispatch_MintTarget_SelfExchange_Disabled_StillRequiresConsent(t *testing.T) {
	setup := newDispatchSetupWithConfig(t, output.TokenExchangeConfig{
		AllowSelfExchange: false,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})
	ctx := context.Background()

	self, selfSecret := setup.createClientWithID(t, "self-disabled", true)
	setup.seedMintResource(t, "tasks-mcp", []string{"tasks.read"}, nil)
	setup.seedUser(t, "user-erin")
	// No consent grant — same shape as the user-subject success test but
	// allow_self_exchange is off.

	subjectClaims := identitySubjectClaims(self.ID)
	subjectClaims.Subject = "user-erin"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         self.ID,
		ClientSecret:     selfSecret,
		Resource:         "tasks-mcp",
		Scope:            "tasks.read",
	})
	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("expected *domain.ConsentRequiredError, got %v", err)
	}
	if cre.Cause != domain.CauseConsentMissing {
		t.Errorf("Cause = %q, want %q", cre.Cause, domain.CauseConsentMissing)
	}
}

// The operator allowlist is orthogonal access control over which
// clients may act on the resource; self-exchange does not bypass it.
// It bites only when the list is non-empty — the counterpart to the
// empty-allowlist test above, which passes with no authorization gate.
func TestTokenExchangeService_Dispatch_MintTarget_SelfExchange_OperatorGate_StillEnforced(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	self, selfSecret := setup.createClientWithID(t, "self-not-allowlisted", true)
	// Allowlist names a different client; self is NOT permitted to act on
	// this resource even though self-exchange is on.
	setup.seedMintResource(t, "restricted-mcp", []string{"x.read"}, []string{"some-other-client"})

	subjectClaims := defaultSubjectClaims(self.ID)
	subjectClaims.Subject = self.ID
	subjectClaims.Scope = "x.read"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         self.ID,
		ClientSecret:     selfSecret,
		Resource:         "restricted-mcp",
		Scope:            "x.read",
	})
	if !errors.Is(err, domain.ErrTokenExchangeNotAuthorized) {
		t.Fatalf("expected ErrTokenExchangeNotAuthorized, got %v", err)
	}
}

// -------------------------------------------------------------------
// Hybrid subject-scope ceiling (ADR-002). When the subject token carries
// an explicit scope claim, registry-dispatched exchanges enforce
// requested ⊆ subject as a ceiling in addition to the consent /
// attestation gate. Identity-only subject tokens skip the ceiling.
// -------------------------------------------------------------------

func TestDispatchMint_SubjectScopeCeiling_RejectsWidening(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	agent, _ := setup.makeAgentClient(t, "agent-ceiling-mint")
	actor, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "")
	mintRes := setup.seedMintResource(t, "ceiling-mcp", []string{"tasks.read", "tasks.admin"}, nil)
	setup.seedUser(t, "user-ceiling-mint")
	// Consent grants BOTH scopes — under the legacy "consent is sole authority"
	// model this would succeed for "tasks.admin". The ceiling must block it
	// because the subject token only carries "tasks.read".
	setup.seedConsentGrant(t, "user-ceiling-mint", agent.ID, mintRes.ID, []string{"tasks.read", "tasks.admin"})

	subjectClaims := defaultSubjectClaims(agent.ID)
	subjectClaims.Subject = "user-ceiling-mint"
	subjectClaims.Scope = "tasks.read"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actor.ID,
		ClientSecret:     actorSecret,
		Resource:         "ceiling-mcp",
		Scope:            "tasks.read tasks.admin",
	})
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Fatalf("err = %v, want ErrInvalidScope (subject-scope ceiling)", err)
	}
}

func TestDispatchMint_SubjectScopeCeiling_AllowsSubset(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	agent, _ := setup.makeAgentClient(t, "agent-ceiling-mint-ok")
	actor, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "")
	mintRes := setup.seedMintResource(t, "ceiling-ok-mcp", []string{"tasks.read", "tasks.write"}, nil)
	setup.seedUser(t, "user-ceiling-ok")
	setup.seedConsentGrant(t, "user-ceiling-ok", agent.ID, mintRes.ID, []string{"tasks.read", "tasks.write"})

	subjectClaims := defaultSubjectClaims(agent.ID)
	subjectClaims.Subject = "user-ceiling-ok"
	subjectClaims.Scope = "tasks.read tasks.write"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	resp, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actor.ID,
		ClientSecret:     actorSecret,
		Resource:         "ceiling-ok-mcp",
		Scope:            "tasks.read",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.Scope != "tasks.read" {
		t.Errorf("scope = %q, want tasks.read", resp.Scope)
	}
}

func TestDispatchBroker_SubjectScopeCeiling_RejectsWidening(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	agent, _ := setup.makeAgentClient(t, "broker-ceiling")
	// Actor client is also seeded as a Mint resource so the broker
	// agent-attestation lookup resolves req.ClientID → actor MCP.
	actor, actorSecret := setup.makeActorClient(t, "broker-ceiling")
	actorMint := setup.seedMintResource(t, actor.ID, []string{"upstream.read", "upstream.admin"}, nil)

	provider := setup.seedBrokerProvider(t, "ceiling-provider")
	setup.seedBrokerResource(t, "ceiling-broker", provider.ID, []string{"upstream.read", "upstream.admin"}, nil)

	setup.seedUser(t, "user-broker-ceiling")
	// Agent-attestation grant covers BOTH scopes — the ceiling must still
	// block the wider request because the subject token only carries one.
	setup.seedConsentGrant(t, "user-broker-ceiling", agent.ID, actorMint.ID, []string{"upstream.read", "upstream.admin"})
	setup.seedBrokerGrant(t, "user-broker-ceiling", provider.ID, []string{"upstream.read", "upstream.admin"})

	subjectClaims := defaultSubjectClaims(agent.ID)
	subjectClaims.Subject = "user-broker-ceiling"
	subjectClaims.Scope = "upstream.read"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actor.ID,
		ClientSecret:     actorSecret,
		Resource:         "ceiling-broker",
		Scope:            "upstream.read upstream.admin",
	})
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Fatalf("err = %v, want ErrInvalidScope (subject-scope ceiling)", err)
	}
}

// Identity-only subject tokens skip the ceiling — the consent grant is
// the sole authority. This confirms the MCP / agent-architecture path
// keeps working after the hybrid model lands.
func TestDispatchMint_SubjectScopeCeiling_IdentityOnly_BypassesCeiling(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	agent, _ := setup.makeAgentClient(t, "agent-identity-bypass")
	actor, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "")
	mintRes := setup.seedMintResource(t, "identity-mcp", []string{"tasks.read", "tasks.write"}, nil)
	setup.seedUser(t, "user-identity")
	setup.seedConsentGrant(t, "user-identity", agent.ID, mintRes.ID, []string{"tasks.read", "tasks.write"})

	subjectClaims := identitySubjectClaims(agent.ID) // no scope claim
	subjectClaims.Subject = "user-identity"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	resp, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actor.ID,
		ClientSecret:     actorSecret,
		Resource:         "identity-mcp",
		// Ask for both — the identity-only ceiling does not fire; consent
		// grant covers both, so issuance succeeds.
		Scope: "tasks.read tasks.write",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.Scope != "tasks.read tasks.write" {
		t.Errorf("scope = %q, want tasks.read tasks.write", resp.Scope)
	}
}

// -------------------------------------------------------------------
// Scoped-subject coverage. The ADR-002 migration moved most dispatch
// tests to identitySubjectClaims (Scope=""), so the consent / operator
// / attestation gates no longer get exercised against scoped subject
// tokens that would otherwise satisfy the ceiling. These tests close
// that gap: each constructs a scoped subject token and verifies a
// non-ceiling gate produces the expected denial — guarding against a
// regression where the ceiling check accidentally absorbs the request
// before consent / operator code paths run, or vice versa.
// -------------------------------------------------------------------

func TestDispatchMint_ScopedSubject_NoConsent_StillReturnsConsentRequired(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	agent, _ := setup.makeAgentClient(t, "scoped-noconsent")
	actor, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "")
	setup.seedMintResource(t, "noconsent-mcp", []string{"tasks.read", "tasks.write"}, nil)
	setup.seedUser(t, "user-scoped-noconsent")
	// Deliberately NO consent grant — even though the ceiling passes, the
	// dispatcher must still raise ConsentRequiredError, not invalid_scope.

	subjectClaims := defaultSubjectClaims(agent.ID)
	subjectClaims.Subject = "user-scoped-noconsent"
	subjectClaims.Scope = "tasks.read tasks.write" // ceiling covers request
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actor.ID,
		ClientSecret:     actorSecret,
		Resource:         "noconsent-mcp",
		Scope:            "tasks.read",
	})
	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("err = %v, want *ConsentRequiredError (ceiling pass + consent missing)", err)
	}
	if cre.Cause != domain.CauseConsentMissing {
		t.Errorf("Cause = %q, want %q", cre.Cause, domain.CauseConsentMissing)
	}
}

func TestDispatchMint_ScopedSubject_OperatorGateRejects(t *testing.T) {
	setup := newDispatchSetup(t)
	ctx := context.Background()

	agent, _ := setup.makeAgentClient(t, "scoped-opgate")
	rejected, rejectedSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "")
	allowed, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "")
	// Operator allowlist names a different client. Even with a covering
	// subject scope and a consent grant, the rejected client must not
	// reach issuance.
	mintRes := setup.seedMintResource(t, "opgate-mcp", []string{"tasks.read"}, []string{allowed.ID})
	setup.seedUser(t, "user-opgate")
	setup.seedConsentGrant(t, "user-opgate", agent.ID, mintRes.ID, []string{"tasks.read"})

	subjectClaims := defaultSubjectClaims(agent.ID)
	subjectClaims.Subject = "user-opgate"
	subjectClaims.Scope = "tasks.read" // ceiling would pass
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         rejected.ID,
		ClientSecret:     rejectedSecret,
		Resource:         "opgate-mcp",
		Scope:            "tasks.read",
	})
	if !errors.Is(err, domain.ErrTokenExchangeNotAuthorized) {
		t.Fatalf("err = %v, want ErrTokenExchangeNotAuthorized (operator gate)", err)
	}
}

// Compile-time sanity: dispatchStubAdapter must satisfy the unified
// BrokerProtocol port (interface lives in internal/ports/output; the
// brokerproto.Registry stores values of that interface type).
var _ output.BrokerProtocol = (*dispatchStubAdapter)(nil)
var _ brokerproto.Registry // referenced to prevent unused-import on early failures
