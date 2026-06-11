//go:build integration

package services_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/authplane/authserver/internal/adapters/keyfile"
	"github.com/authplane/authserver/internal/brokerproto"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

const teIssuer = "https://auth.example.com"

type teTestSetup struct {
	svc      *services.TokenExchangeService
	jwksSvc  *services.JWKSService
	auditSvc *services.AuditService
	h        *testdata.TestHelper
	obs      *observability.Provider
	kp       *crypto.KeyPair // signing key for minting subject tokens
}

// teTestEncryptor is a no-op DataEncryptor used in TokenExchangeService unit
// tests where the BrokerIssuer is wired but never invoked (req.Resource == ""
// requests bypass it; resource-targeted requests go through dispatch tests
// that supply their own encryptor).
type teTestEncryptor struct{}

func (teTestEncryptor) Encrypt(_ context.Context, plaintext []byte, _ string) ([]byte, error) {
	return plaintext, nil
}
func (teTestEncryptor) Decrypt(_ context.Context, ciphertext []byte, _ string) ([]byte, error) {
	return ciphertext, nil
}
func (teTestEncryptor) DriverName() string { return "te-test" }

func newTETestSetup(t *testing.T, cfg services.TokenExchangeConfig) *teTestSetup {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	dir := t.TempDir()
	ks, err := keyfile.New(dir, obs)
	if err != nil {
		t.Fatalf("keyfile: %v", err)
	}

	jwksSvc := services.NewJWKSService(ks, "ES256", obs)
	auditSvc := services.NewAuditService(stores.Audit, obs)

	// : registry-or-bust. Wire a live ResourceRegistry, MintIssuer,
	// and BrokerIssuer over the same test stores so non-dispatch tests
	// (which call req.Resource == "") still construct cleanly.
	registry := services.NewResourceRegistry(stores.Resource, stores.BrokerProvider, obs)
	mintIssuer := services.NewMintIssuer(jwksSvc, stores.Issuance, teIssuer, obs)
	bpReg := brokerproto.NewRegistry()
	enc := &teTestEncryptor{}
	brokerIssuer := services.NewBrokerIssuer(stores.BrokerGrant, enc, stores.Issuance, bpReg, obs, auditSvc)

	svc := services.NewTokenExchangeService(
		stores.Client,
		stores.MachineToken,
		jwksSvc,
		jwksSvc,
		stores.Revocation,
		teIssuer,
		cfg,
		registry,
		stores.ConsentGrant,
		mintIssuer,
		brokerIssuer,
		obs,
		auditSvc,
	)

	// Pre-generate a signing key so BuildJWKS works for verification.
	ctx := context.Background()
	sk, err := jwksSvc.GetSigningKey(ctx)
	if err != nil {
		t.Fatalf("get signing key: %v", err)
	}

	kp := &crypto.KeyPair{
		PrivateKey: sk.PrivateKey,
		PublicKey:  sk.PublicKey,
		Algorithm:  jose.SignatureAlgorithm(sk.Algorithm),
		KeyID:      sk.KeyID,
	}

	return &teTestSetup{
		svc:      svc,
		jwksSvc:  jwksSvc,
		auditSvc: auditSvc,
		h:        &testdata.TestHelper{Stores: stores},
		obs:      obs,
		kp:       kp,
	}
}

// createTEClient creates a confidential client with the given grant types.
func (s *teTestSetup) createTEClient(t *testing.T, grantTypes []string, scopeStr string) (*client.Client, string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	secret := crypto.GenerateClientSecret()
	hash, err := crypto.HashBcrypt(secret)
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}

	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		SecretHash:              hash,
		Name:                    "TE Test Client",
		RedirectURIs:            []string{},
		GrantTypes:              grantTypes,
		ResponseTypes:           []string{},
		TokenEndpointAuthMethod: "client_secret_basic",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceAdmin,
		Scope:                   scopeStr,
		IssuedAt:                now,
		UpdatedAt:               now,
	}

	if err := s.h.Stores.Client.Create(ctx, c); err != nil {
		t.Fatalf("create client: %v", err)
	}
	return c, secret
}

// mintSubjectToken signs a subject token JWT that the token exchange service can verify.
func (s *teTestSetup) mintSubjectToken(t *testing.T, claims crypto.AccessTokenClaims) string {
	t.Helper()

	accessToken, err := crypto.SignAccessToken(s.kp, claims)
	if err != nil {
		t.Fatalf("sign subject token: %v", err)
	}
	return accessToken
}

// defaultSubjectClaims returns a valid set of subject token claims with an
// explicit scope claim. Used by the legacy (req.Resource == "") tests where
// the subject token's scope is the only authority bound (RFC 8693 subset
// containment).
func defaultSubjectClaims(clientID string) crypto.AccessTokenClaims {
	now := time.Now().UTC()
	return crypto.AccessTokenClaims{
		Issuer:    teIssuer,
		Subject:   "user-123",
		Audience:  []string{teIssuer},
		ClientID:  clientID,
		Scope:     "read write delete",
		JTI:       crypto.GenerateRandomString(16),
		IssuedAt:  now.Unix(),
		Expiry:    now.Add(1 * time.Hour).Unix(),
		NotBefore: now.Unix(),
	}
}

// identitySubjectClaims returns subject claims with no scope claim, modeling
// the identity-only token shape used by registry-dispatched exchanges in
// production (auth code → ID token, federation assertion, session token).
// Under the hybrid authority model (ADR-002), identity-only subject tokens
// skip the RFC 8693 narrowing ceiling and rely on the dispatcher's consent
// or attestation grant as the sole authority for the resulting token scope.
// Tests that want to exercise the ceiling explicitly should not use this
// helper — they should construct claims with a non-empty Scope.
func identitySubjectClaims(clientID string) crypto.AccessTokenClaims {
	c := defaultSubjectClaims(clientID)
	c.Scope = ""
	return c
}

// parseClaims parses the JWT response and returns raw claims map.
func parseClaims(t *testing.T, accessToken string) map[string]any {
	t.Helper()
	tok, err := jwt.ParseSigned(accessToken, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse JWT: %v", err)
	}
	var claims map[string]any
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		t.Fatalf("unsafe claims: %v", err)
	}
	return claims
}

// -------------------------------------------------------------------
// Test 1: Impersonation — no actor token, no act claim in output
// -------------------------------------------------------------------
func TestTokenExchange_Impersonation_NoActClaim(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	subClient, subSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write delete")
	subjectClaims := defaultSubjectClaims(subClient.ID)
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	resp, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         subClient.ID,
		ClientSecret:     subSecret,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	if resp.IssuedTokenType != token.TokenTypeAccessToken {
		t.Errorf("issued_token_type = %q, want %q", resp.IssuedTokenType, token.TokenTypeAccessToken)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", resp.TokenType)
	}

	claims := parseClaims(t, resp.AccessToken)
	if claims["sub"] != "user-123" {
		t.Errorf("sub = %v, want user-123", claims["sub"])
	}
	if claims["act"] != nil {
		t.Errorf("act should be nil for impersonation, got %v", claims["act"])
	}
}

// -------------------------------------------------------------------
// Test 2: Delegation — actor token present, builds act claim
// -------------------------------------------------------------------
func TestTokenExchange_Delegation_BuildsActClaim(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	subClient, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	actorClient, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	subjectClaims := defaultSubjectClaims(subClient.ID)
	subjectClaims.MayAct = map[string]interface{}{"sub": actorClient.ID}
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	actorClaims := defaultSubjectClaims(actorClient.ID)
	actorClaims.Subject = actorClient.ID // machine token style
	actorToken := setup.mintSubjectToken(t, actorClaims)

	resp, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ActorToken:       actorToken,
		ActorTokenType:   token.TokenTypeAccessToken,
		ClientID:         actorClient.ID,
		ClientSecret:     actorSecret,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	claims := parseClaims(t, resp.AccessToken)
	if claims["sub"] != "user-123" {
		t.Errorf("sub = %v, want user-123", claims["sub"])
	}

	actMap, ok := claims["act"].(map[string]any)
	if !ok {
		t.Fatalf("act claim missing or wrong type: %T", claims["act"])
	}
	if actMap["sub"] != actorClient.ID {
		t.Errorf("act.sub = %v, want %q", actMap["sub"], actorClient.ID)
	}
}

// -------------------------------------------------------------------
// Test 3: Multi-hop — chain nests existing act claim
// -------------------------------------------------------------------
func TestTokenExchange_MultiHop_ChainNested(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	// Client A issued the original subject token with an existing act claim from Agent-1.
	clientA, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	clientB, clientBSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	subjectClaims := defaultSubjectClaims(clientA.ID)
	// Pre-populate an act claim: Agent-1 already acted.
	subjectClaims.Act = token.ActClaimToMap(&token.ActClaim{Sub: "agent-1-id"})
	subjectClaims.MayAct = map[string]interface{}{"sub": clientB.ID}
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	actorClaims := defaultSubjectClaims(clientB.ID)
	actorClaims.Subject = clientB.ID
	actorToken := setup.mintSubjectToken(t, actorClaims)

	resp, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ActorToken:       actorToken,
		ActorTokenType:   token.TokenTypeAccessToken,
		ClientID:         clientB.ID,
		ClientSecret:     clientBSecret,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	claims := parseClaims(t, resp.AccessToken)

	// The act chain should be: { sub: clientB.ID, act: { sub: "agent-1-id" } }
	actMap, ok := claims["act"].(map[string]any)
	if !ok {
		t.Fatalf("act claim missing or wrong type: %T", claims["act"])
	}
	if actMap["sub"] != clientB.ID {
		t.Errorf("act.sub = %v, want %q", actMap["sub"], clientB.ID)
	}

	nested, ok := actMap["act"].(map[string]any)
	if !ok {
		t.Fatalf("act.act missing or wrong type: %T", actMap["act"])
	}
	if nested["sub"] != "agent-1-id" {
		t.Errorf("act.act.sub = %v, want agent-1-id", nested["sub"])
	}
}

// -------------------------------------------------------------------
// Test 4: Scope narrowing — subset allowed
// -------------------------------------------------------------------
func TestTokenExchange_ScopeNarrowing_SubsetAllowed(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write delete")
	subjectClaims := defaultSubjectClaims(c.ID)
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	resp, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		Scope:            "read",
		ClientID:         c.ID,
		ClientSecret:     secret,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	if resp.Scope != "read" {
		t.Errorf("scope = %q, want read", resp.Scope)
	}
}

// -------------------------------------------------------------------
// Test 5: Scope escalation — rejected
// -------------------------------------------------------------------
func TestTokenExchange_ScopeEscalation_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write delete admin")
	subjectClaims := defaultSubjectClaims(c.ID)
	subjectClaims.Scope = "read" // Subject token only has "read"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		Scope:            "read admin", // "admin" not in subject token
		ClientID:         c.ID,
		ClientSecret:     secret,
	})
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Errorf("err = %v, want ErrInvalidScope", err)
	}
}

// -------------------------------------------------------------------
// Test 6: Expired subject token — rejected
// -------------------------------------------------------------------
func TestTokenExchange_ExpiredSubjectToken_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	subjectClaims := defaultSubjectClaims(c.ID)
	subjectClaims.Expiry = time.Now().Add(-1 * time.Hour).Unix() // Expired
	subjectClaims.IssuedAt = time.Now().Add(-2 * time.Hour).Unix()
	subjectClaims.NotBefore = time.Now().Add(-2 * time.Hour).Unix()
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
	})
	if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("err = %v, want ErrInvalidGrant", err)
	}
}

// -------------------------------------------------------------------
// Test 7: Foreign AS issuer — rejected
// -------------------------------------------------------------------
func TestTokenExchange_ForeignASIssuer_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	subjectClaims := defaultSubjectClaims(c.ID)
	subjectClaims.Issuer = "https://evil.example.com" // Wrong issuer
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
	})
	if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("err = %v, want ErrInvalidGrant", err)
	}
}

// -------------------------------------------------------------------
// Test 8: Self-exchange — allowed when configured
// -------------------------------------------------------------------
func TestTokenExchange_SelfExchange_Allowed(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	subjectClaims := defaultSubjectClaims(c.ID)
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	resp, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	claims := parseClaims(t, resp.AccessToken)
	if claims["sub"] != "user-123" {
		t.Errorf("sub = %v, want user-123", claims["sub"])
	}
	if claims["client_id"] != c.ID {
		t.Errorf("client_id = %v, want %q", claims["client_id"], c.ID)
	}
}

// -------------------------------------------------------------------
// Test 9: Cross-client may_act — allowed
// -------------------------------------------------------------------
func TestTokenExchange_CrossClient_MayAct_Allowed(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: false, // self-exchange disabled
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	subClient, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	actorClient, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	// Subject token has may_act authorizing actorClient.
	subjectClaims := defaultSubjectClaims(subClient.ID)
	subjectClaims.MayAct = map[string]interface{}{"sub": actorClient.ID}
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	resp, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actorClient.ID,
		ClientSecret:     actorSecret,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	if resp.AccessToken == "" {
		t.Error("access_token is empty")
	}
}

// -------------------------------------------------------------------
// Test 10: Cross-client not authorized — rejected
// -------------------------------------------------------------------
func TestTokenExchange_CrossClient_NotAuthorized_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: false,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	subClient, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	actorClient, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	// Subject token has no may_act and self-exchange is disabled — the
	// surviving cross-client paths after  (may_act + the unified
	// per-Resource operator gate) both refuse, so checkPolicy() rejects.
	subjectClaims := defaultSubjectClaims(subClient.ID)
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actorClient.ID,
		ClientSecret:     actorSecret,
	})
	if !errors.Is(err, domain.ErrTokenExchangeNotAuthorized) {
		t.Errorf("err = %v, want ErrTokenExchangeNotAuthorized", err)
	}
}

// -------------------------------------------------------------------
// Test 12: Chain depth limit — enforced
// -------------------------------------------------------------------
func TestTokenExchange_ChainDepthLimit_Enforced(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     2, // Depth limit = 2
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	// Subject token already has a 2-deep act chain (agent-2 -> agent-1).
	subjectClaims := defaultSubjectClaims(c.ID)
	subjectClaims.Act = token.ActClaimToMap(&token.ActClaim{
		Sub: "agent-2",
		Act: &token.ActClaim{Sub: "agent-1"},
	})
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	// Actor token for delegation — this would push depth to 3, exceeding limit of 2.
	actorClaims := defaultSubjectClaims(c.ID)
	actorClaims.Subject = c.ID
	actorToken := setup.mintSubjectToken(t, actorClaims)

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ActorToken:       actorToken,
		ActorTokenType:   token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
	})
	if !errors.Is(err, domain.ErrTokenExchangeChainTooDeep) {
		t.Errorf("err = %v, want ErrTokenExchangeChainTooDeep", err)
	}
}

// -------------------------------------------------------------------
// Test 12b: Chain depth limit — enforced without actor_token (self-exchange)
// Prevents laundering delegation chain via self-exchange omitting actor_token.
// -------------------------------------------------------------------
func TestTokenExchange_ChainDepthLimit_EnforcedWithoutActorToken(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     1,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	subjectClaims := defaultSubjectClaims(c.ID)
	subjectClaims.Act = token.ActClaimToMap(&token.ActClaim{
		Sub: "agent-2",
		Act: &token.ActClaim{Sub: "agent-1"},
	})
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
	})
	if !errors.Is(err, domain.ErrTokenExchangeChainTooDeep) {
		t.Errorf("err = %v, want ErrTokenExchangeChainTooDeep", err)
	}
}

// -------------------------------------------------------------------
// Test 12c: Self-exchange with delegated subject preserves act claim
// -------------------------------------------------------------------
func TestTokenExchange_SelfExchangeWithDelegatedSubject_PreservesActClaim(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	subjectClaims := defaultSubjectClaims(c.ID)
	subjectClaims.Act = token.ActClaimToMap(&token.ActClaim{Sub: "agent-1"})
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	resp, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	claims := parseClaims(t, resp.AccessToken)
	actMap, ok := claims["act"].(map[string]any)
	if !ok {
		t.Fatalf("act claim missing or wrong type: %T", claims["act"])
	}
	if actMap["sub"] != "agent-1" {
		t.Errorf("act.sub = %v, want agent-1", actMap["sub"])
	}
}

// -------------------------------------------------------------------
// Test 13: DPoP-bound subject token — propagates cnf
// -------------------------------------------------------------------
func TestTokenExchange_DPoPBoundSubject_PropagatesCNF(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	subjectClaims := defaultSubjectClaims(c.ID)
	subjectClaims.Cnf = map[string]interface{}{"jkt": "original-thumbprint-abc123"}
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	resp, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
		// No DPoPProof — should propagate subject's cnf
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	if resp.TokenType != "DPoP" {
		t.Errorf("token_type = %q, want DPoP (cnf propagated)", resp.TokenType)
	}

	claims := parseClaims(t, resp.AccessToken)
	cnf, ok := claims["cnf"].(map[string]any)
	if !ok {
		t.Fatalf("cnf claim missing or wrong type: %T", claims["cnf"])
	}
	if cnf["jkt"] != "original-thumbprint-abc123" {
		t.Errorf("cnf.jkt = %v, want original-thumbprint-abc123", cnf["jkt"])
	}
}

// Suppress "unused import" for json — it's used by parseClaims indirectly via jwt.
var _ = json.RawMessage{}

// -------------------------------------------------------------------
// Resource-aware scope validation tests
// -------------------------------------------------------------------

// newTETestSetupWithResources creates a token exchange test setup with resource-aware scope validation.
func newTETestSetupWithResources(t *testing.T, cfg services.TokenExchangeConfig, resources []services.ResourceInfo) *teTestSetup {
	t.Helper()
	setup := newTETestSetup(t, cfg)
	// Enable resource-aware scope validation using the configured resources and the scope store.
	setup.svc.WithResourceScopes(services.NewStaticResourceLister(resources))
	return setup
}

// The legacy validateScopesForResource fall-through is retired (the
// req.Resource path is now registry-or-bust). The dispatch tests in
// token_exchange_dispatch_test.go::TestTokenExchangeService_Dispatch_ScopeNotInCatalog_Rejected
// cover scope-against-catalog validation through the unified Mint/Broker
// dispatch instead. Four legacy tests that asserted the deleted code
// path were removed during the cleanup.

func TestTokenExchange_NoResource_SubsetCheckStillWorks(t *testing.T) {
	// With resources configured but no resource in the request,
	// the old subset check should still apply.
	resources := []services.ResourceInfo{
		{URI: "https://api.target.com", Scopes: []string{"admin"}},
	}
	setup := newTETestSetupWithResources(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	}, resources)

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	subjectClaims := defaultSubjectClaims(c.ID)
	subjectClaims.Scope = "read write"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	// Request "read" with no resource — should use strict subset check against subject token.
	resp, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
		Scope:            "read",
	})
	if err != nil {
		t.Fatalf("exchange should succeed for subset scope without resource: %v", err)
	}
	if resp.Scope != "read" {
		t.Errorf("scope: got %q, want %q", resp.Scope, "read")
	}

	// Request "admin" with no resource — should fail because it is not a subset of subject token's scope.
	_, err = setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
		Scope:            "admin",
	})
	if err == nil {
		t.Fatal("exchange should fail for scope escalation without resource")
	}
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Errorf("expected ErrInvalidScope, got: %v", err)
	}
}

func TestTokenExchange_SubjectTokenIssuerValidation(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	// Subject token has a different issuer (simulates cross-issuer confusion).
	subjectClaims := defaultSubjectClaims(c.ID)
	subjectClaims.Issuer = "https://other-as.example.com"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
		Scope:            "read",
	})
	if err == nil {
		t.Fatal("exchange should reject subject token whose issuer does not match this AS")
	}
	if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("expected ErrInvalidGrant, got: %v", err)
	}
}

func TestTokenExchange_ResourceScopedSubjectToken_Accepted(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	// Subject token has aud=[resource] (not the AS issuer) — this is the normal
	// flow when tokens are issued with a resource parameter.
	subjectClaims := defaultSubjectClaims(c.ID)
	subjectClaims.Audience = []string{"https://api.gateway.example.com"}
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	resp, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
		Scope:            "read",
	})
	if err != nil {
		t.Fatalf("exchange should accept resource-scoped subject token: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("expected non-empty access_token")
	}
}

func TestTokenExchange_MissingSubjectToken(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     "",
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
		Scope:            "read",
	})
	if err == nil {
		t.Fatal("exchange should reject empty subject_token")
	}
	if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("expected ErrInvalidGrant, got: %v", err)
	}
}

// ===================================================================
// CLIENT AUTHENTICATION FAILURE TESTS
// ===================================================================

func TestTokenExchange_EmptyClientID_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	subjectToken := setup.mintSubjectToken(t, defaultSubjectClaims(c.ID))

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         "",
		ClientSecret:     "some-secret",
	})
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("err = %v, want ErrInvalidClient", err)
	}
}

func TestTokenExchange_EmptyClientSecret_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	subjectToken := setup.mintSubjectToken(t, defaultSubjectClaims(c.ID))

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     "",
	})
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("err = %v, want ErrInvalidClient", err)
	}
}

func TestTokenExchange_WrongClientSecret_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	subjectToken := setup.mintSubjectToken(t, defaultSubjectClaims(c.ID))

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     "totally-wrong-secret",
	})
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("err = %v, want ErrInvalidClient", err)
	}
}

func TestTokenExchange_SuspendedClient_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	subjectToken := setup.mintSubjectToken(t, defaultSubjectClaims(c.ID))

	// Suspend the client after creation.
	ctx := context.Background()
	c.Status = client.StatusSuspended
	if err := setup.h.Stores.Client.Update(ctx, c); err != nil {
		t.Fatalf("suspend client: %v", err)
	}

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
	})
	if !errors.Is(err, domain.ErrClientSuspended) {
		t.Errorf("err = %v, want ErrClientSuspended", err)
	}
}

func TestTokenExchange_PublicClient_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	// Create a public client (no secret hash).
	ctx := context.Background()
	now := time.Now().UTC()
	pubClient := &client.Client{
		ID:                      crypto.GenerateClientID(),
		SecretHash:              "", // public client — no secret
		Name:                    "Public Client",
		RedirectURIs:            []string{"http://localhost:9999/callback"},
		GrantTypes:              []string{token.GrantTypeTokenExchange},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceAdmin,
		Scope:                   "read write",
		IssuedAt:                now,
		UpdatedAt:               now,
	}
	if err := setup.h.Stores.Client.Create(ctx, pubClient); err != nil {
		t.Fatalf("create public client: %v", err)
	}

	subjectToken := setup.mintSubjectToken(t, defaultSubjectClaims(pubClient.ID))

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         pubClient.ID,
		ClientSecret:     "anything", // won't matter — public clients are rejected early
	})
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("err = %v, want ErrInvalidClient (public client cannot use token exchange)", err)
	}
}

func TestTokenExchange_ClientNotFound_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	subjectToken := setup.mintSubjectToken(t, defaultSubjectClaims(c.ID))

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         "nonexistent-client-id",
		ClientSecret:     "some-secret",
	})
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("err = %v, want ErrInvalidClient", err)
	}
}

// ===================================================================
// GRANT TYPE AUTHORIZATION TESTS
// ===================================================================

func TestTokenExchange_ClientWithoutTokenExchangeGrant_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	// Client only has authorization_code — NOT token_exchange.
	c, secret := setup.createTEClient(t, []string{"authorization_code"}, "read write")
	subjectClaims := defaultSubjectClaims(c.ID)
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
	})
	if !errors.Is(err, domain.ErrUnauthorizedClient) {
		t.Errorf("err = %v, want ErrUnauthorizedClient", err)
	}
}

// ===================================================================
// TOKEN TYPE VALIDATION TESTS
// ===================================================================

func TestTokenExchange_InvalidSubjectTokenType_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	subjectToken := setup.mintSubjectToken(t, defaultSubjectClaims(c.ID))

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: "urn:invalid:type",
		ClientID:         c.ID,
		ClientSecret:     secret,
	})
	if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("err = %v, want ErrInvalidGrant", err)
	}
}

func TestTokenExchange_EmptySubjectTokenType_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	subjectToken := setup.mintSubjectToken(t, defaultSubjectClaims(c.ID))

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: "",
		ClientID:         c.ID,
		ClientSecret:     secret,
	})
	if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("err = %v, want ErrInvalidGrant", err)
	}
}

func TestTokenExchange_RefreshTokenType_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	subjectToken := setup.mintSubjectToken(t, defaultSubjectClaims(c.ID))

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeRefreshToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
	})
	if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("err = %v, want ErrInvalidGrant (refresh_token type is not valid for subject tokens)", err)
	}
}

// ===================================================================
// ACTOR TOKEN FAILURE TESTS
// ===================================================================

func TestTokenExchange_ExpiredActorToken_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	subClient, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	actorClient, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	subjectClaims := defaultSubjectClaims(subClient.ID)
	subjectClaims.MayAct = map[string]interface{}{"sub": actorClient.ID}
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	// Actor token is expired.
	actorClaims := defaultSubjectClaims(actorClient.ID)
	actorClaims.Subject = actorClient.ID
	actorClaims.Expiry = time.Now().Add(-1 * time.Hour).Unix()
	actorClaims.IssuedAt = time.Now().Add(-2 * time.Hour).Unix()
	actorClaims.NotBefore = time.Now().Add(-2 * time.Hour).Unix()
	actorToken := setup.mintSubjectToken(t, actorClaims)

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ActorToken:       actorToken,
		ActorTokenType:   token.TokenTypeAccessToken,
		ClientID:         actorClient.ID,
		ClientSecret:     actorSecret,
	})
	if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("err = %v, want ErrInvalidGrant (expired actor token)", err)
	}
}

func TestTokenExchange_MalformedActorToken_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	subClient, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	actorClient, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	subjectClaims := defaultSubjectClaims(subClient.ID)
	subjectClaims.MayAct = map[string]interface{}{"sub": actorClient.ID}
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ActorToken:       "not-a-valid-jwt",
		ActorTokenType:   token.TokenTypeAccessToken,
		ClientID:         actorClient.ID,
		ClientSecret:     actorSecret,
	})
	if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("err = %v, want ErrInvalidGrant (malformed actor token)", err)
	}
}

func TestTokenExchange_ActorTokenDifferentIssuer_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	subClient, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	actorClient, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	subjectClaims := defaultSubjectClaims(subClient.ID)
	subjectClaims.MayAct = map[string]interface{}{"sub": actorClient.ID}
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	// Actor token has wrong issuer — VerifyAccessTokenWithIssuer will reject it.
	actorClaims := defaultSubjectClaims(actorClient.ID)
	actorClaims.Subject = actorClient.ID
	actorClaims.Issuer = "https://evil.example.com"
	actorToken := setup.mintSubjectToken(t, actorClaims)

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ActorToken:       actorToken,
		ActorTokenType:   token.TokenTypeAccessToken,
		ClientID:         actorClient.ID,
		ClientSecret:     actorSecret,
	})
	if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("err = %v, want ErrInvalidGrant (actor token from different issuer)", err)
	}
}

func TestTokenExchange_InvalidActorTokenType_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	subClient, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	actorClient, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	subjectClaims := defaultSubjectClaims(subClient.ID)
	subjectClaims.MayAct = map[string]interface{}{"sub": actorClient.ID}
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	actorClaims := defaultSubjectClaims(actorClient.ID)
	actorClaims.Subject = actorClient.ID
	actorToken := setup.mintSubjectToken(t, actorClaims)

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ActorToken:       actorToken,
		ActorTokenType:   "urn:invalid:actor-type",
		ClientID:         actorClient.ID,
		ClientSecret:     actorSecret,
	})
	if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("err = %v, want ErrInvalidGrant (invalid actor_token_type)", err)
	}
}

// ===================================================================
// REVOCATION CHECK TESTS
// ===================================================================

func TestTokenExchange_RevokedMachineSubjectToken_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	// Create a machine token (sub == client_id).
	jti := crypto.GenerateRandomString(16)
	subjectClaims := defaultSubjectClaims(c.ID)
	subjectClaims.Subject = c.ID // machine token
	subjectClaims.JTI = jti
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	// Store it in MachineTokenStore, then revoke it.
	ctx := context.Background()
	mt := token.MachineToken{
		JTI:       jti,
		ClientID:  c.ID,
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
		Revoked:   true, // already revoked
	}
	if err := setup.h.Stores.MachineToken.Save(ctx, mt); err != nil {
		t.Fatalf("save machine token: %v", err)
	}

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
	})
	if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("err = %v, want ErrInvalidGrant (revoked machine token)", err)
	}
}

func TestTokenExchange_RevokedUserSubjectToken_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	// Create a user token (sub != client_id) with a specific JTI.
	jti := crypto.GenerateRandomString(16)
	subjectClaims := defaultSubjectClaims(c.ID)
	subjectClaims.JTI = jti
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	// Revoke the JTI in the revocation store.
	ctx := context.Background()
	// token_families.user_id is FK-enforced.
	testdata.EnsureUser(t, setup.h.Stores.User, "user-1")
	// Family must exist due to FK constraint.
	if err := setup.h.Stores.Token.CreateFamily(ctx, &token.Family{
		ID:        "family-1",
		ClientID:  c.ID,
		UserID:    "user-1",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create family: %v", err)
	}
	// First track it, then revoke it.
	if err := setup.h.Stores.Revocation.TrackJTI(ctx, jti, "family-1", time.Now().Add(1*time.Hour)); err != nil {
		t.Fatalf("track JTI: %v", err)
	}
	if err := setup.h.Stores.Revocation.RevokeJTI(ctx, jti); err != nil {
		t.Fatalf("revoke JTI: %v", err)
	}

	_, err := setup.svc.Exchange(ctx, input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
	})
	if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("err = %v, want ErrInvalidGrant (revoked user token)", err)
	}
}

// Note: TestTokenExchange_EmptyJTI_SkipsRevocationCheck is not possible to test
// at this level because SignAccessToken requires a non-empty JTI claim. The
// checkRevocation short-circuit for empty JTI (line 577) is a defensive guard
// against tokens from external sources that might lack a JTI. The code path
// is verified by inspection — the guard is a single nil-check early return.

// ===================================================================
// SCOPE EDGE CASE TESTS
// ===================================================================

func TestTokenExchange_EmptyScope_InheritsSubjectTokenScope(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write delete")
	subjectClaims := defaultSubjectClaims(c.ID)
	subjectClaims.Scope = "read write"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	resp, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
		// No Scope — should inherit subject token's scope.
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Scope != "read write" {
		t.Errorf("scope = %q, want %q (inherited from subject token)", resp.Scope, "read write")
	}
}

func TestTokenExchange_NoResource_InheritsSubjectAudience(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	subjectClaims := defaultSubjectClaims(c.ID)
	subjectClaims.Audience = []string{"https://gateway.example.com"}
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	resp, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
		// No Resource — should inherit subject token's audience.
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	claims := parseClaims(t, resp.AccessToken)
	aud, ok := claims["aud"].([]interface{})
	if !ok || len(aud) == 0 {
		t.Fatalf("aud missing or wrong type: %v", claims["aud"])
	}
	if aud[0] != "https://gateway.example.com" {
		t.Errorf("aud[0] = %v, want https://gateway.example.com (inherited from subject)", aud[0])
	}
}

// Note: TestTokenExchange_NoResource_NoSubjectAudience_UsesIssuer cannot be tested
// because SignAccessToken requires a non-empty aud claim. The issuer fallback at
// line 309 is a defensive guard for edge cases where a subject token somehow has
// an empty audience. The code path exists as defense-in-depth.

func TestTokenExchange_SingleScopeSubset_Accepted(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write delete")
	subjectClaims := defaultSubjectClaims(c.ID)
	subjectClaims.Scope = "read write delete"
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	resp, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		Scope:            "read",
		ClientID:         c.ID,
		ClientSecret:     secret,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Scope != "read" {
		t.Errorf("scope = %q, want read", resp.Scope)
	}
}

// ===================================================================
// POLICY EDGE CASE TESTS
// ===================================================================

func TestTokenExchange_SelfExchange_Denied(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: false, // explicitly disabled
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	subjectClaims := defaultSubjectClaims(c.ID)
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
	})
	if !errors.Is(err, domain.ErrTokenExchangeNotAuthorized) {
		t.Errorf("err = %v, want ErrTokenExchangeNotAuthorized (self-exchange disabled)", err)
	}
}

func TestTokenExchange_MayAct_WrongActorSub_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: false,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	subClient, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	actorClientA, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	actorClientB, actorBSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	// Subject token authorizes clientA — but clientB tries to exchange it.
	subjectClaims := defaultSubjectClaims(subClient.ID)
	subjectClaims.MayAct = map[string]interface{}{"sub": actorClientA.ID}
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actorClientB.ID,
		ClientSecret:     actorBSecret,
	})
	if !errors.Is(err, domain.ErrTokenExchangeNotAuthorized) {
		t.Errorf("err = %v, want ErrTokenExchangeNotAuthorized (may_act.sub mismatch)", err)
	}
}

func TestTokenExchange_MayAct_MalformedField_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: false,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	subClient, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	actorClient, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	// Subject token has malformed may_act (sub is an integer, not string).
	subjectClaims := defaultSubjectClaims(subClient.ID)
	subjectClaims.MayAct = map[string]interface{}{"sub": 12345} // wrong type
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         actorClient.ID,
		ClientSecret:     actorSecret,
	})
	// Should be denied: type assertion fails, falls through to allowlist (empty) → denied.
	if !errors.Is(err, domain.ErrTokenExchangeNotAuthorized) {
		t.Errorf("err = %v, want ErrTokenExchangeNotAuthorized (malformed may_act)", err)
	}
}

// ===================================================================
// MALFORMED INPUT TESTS
// ===================================================================

func TestTokenExchange_MalformedSubjectToken_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     "not-a-valid-jwt",
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
	})
	if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("err = %v, want ErrInvalidGrant (malformed subject token)", err)
	}
}

func TestTokenExchange_SubjectTokenSignedByDifferentKey_Rejected(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	// Sign a token with a DIFFERENT key (not in the JWKS).
	foreignKP, err := crypto.GenerateKeyPair("ES256", "foreign-key")
	if err != nil {
		t.Fatalf("generate foreign key: %v", err)
	}
	subjectClaims := defaultSubjectClaims(c.ID)
	foreignToken, err := crypto.SignAccessToken(foreignKP, subjectClaims)
	if err != nil {
		t.Fatalf("sign with foreign key: %v", err)
	}

	_, err = setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     foreignToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
	})
	if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("err = %v, want ErrInvalidGrant (token signed by foreign key)", err)
	}
}

// ===================================================================
// DPOP TESTS
// ===================================================================

func TestTokenExchange_DPoPProof_OverridesSubjectCnf(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	// Subject token has an existing cnf binding.
	subjectClaims := defaultSubjectClaims(c.ID)
	subjectClaims.Cnf = map[string]interface{}{"jkt": "old-thumbprint"}
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	// Exchange WITHOUT a new DPoP proof — should propagate old cnf.
	resp, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	claims := parseClaims(t, resp.AccessToken)
	cnf, ok := claims["cnf"].(map[string]any)
	if !ok {
		t.Fatalf("cnf claim missing or wrong type: %T", claims["cnf"])
	}
	if cnf["jkt"] != "old-thumbprint" {
		t.Errorf("cnf.jkt = %v, want old-thumbprint (propagated from subject)", cnf["jkt"])
	}
}

// ===================================================================
// AUDIT EVENT VERIFICATION TESTS
// ===================================================================

func TestTokenExchange_AuditEvent_RecordedOnSuccess(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	subjectClaims := defaultSubjectClaims(c.ID)
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	// Check audit store for the token_exchanged event.
	ctx := context.Background()
	events, err := setup.h.Stores.Audit.Query(ctx, output.AuditFilter{
		Action: string(audit.ActionTokenExchanged),
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("query audit events: %v", err)
	}
	if len(events) == 0 {
		t.Error("expected audit event with action=token_exchanged, none found")
	}
}

func TestTokenExchange_AuditEvent_RecordedOnDenial(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: false, // self-exchange disabled to trigger denial
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	subjectClaims := defaultSubjectClaims(c.ID)
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	_, _ = setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
	})

	// Check audit store for the denied event.
	ctx := context.Background()
	events, err := setup.h.Stores.Audit.Query(ctx, output.AuditFilter{
		Action: string(audit.ActionTokenExchangeDenied),
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("query audit events: %v", err)
	}
	if len(events) == 0 {
		t.Error("expected audit event with action=token_exchange_denied, none found")
	}
}

// -------------------------------------------------------------------
// actor_type stamping on new outermost hop
// -------------------------------------------------------------------

// setClientAgent flips the IsAgent flag on an already-persisted client.
func (s *teTestSetup) setClientAgent(t *testing.T, clientID string, isAgent bool) {
	t.Helper()
	ctx := context.Background()
	c, err := s.h.Stores.Client.GetByID(ctx, clientID)
	if err != nil {
		t.Fatalf("get client %s: %v", clientID, err)
	}
	c.IsAgent = isAgent
	if err := s.h.Stores.Client.Update(ctx, c); err != nil {
		t.Fatalf("update client %s: %v", clientID, err)
	}
}

func TestTokenExchange_StampsActorTypeAgent_ForAgentClient(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	subClient, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	actorClient, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	setup.setClientAgent(t, actorClient.ID, true)

	subjectClaims := defaultSubjectClaims(subClient.ID)
	subjectClaims.MayAct = map[string]interface{}{"sub": actorClient.ID}
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	actorClaims := defaultSubjectClaims(actorClient.ID)
	actorClaims.Subject = actorClient.ID
	actorToken := setup.mintSubjectToken(t, actorClaims)

	resp, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ActorToken:       actorToken,
		ActorTokenType:   token.TokenTypeAccessToken,
		ClientID:         actorClient.ID,
		ClientSecret:     actorSecret,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	claims := parseClaims(t, resp.AccessToken)
	actMap, ok := claims["act"].(map[string]any)
	if !ok {
		t.Fatalf("act missing or wrong type: %T", claims["act"])
	}
	if actMap["actor_type"] != "agent" {
		t.Errorf("act.actor_type = %v, want agent", actMap["actor_type"])
	}
	if actMap["sub"] != actorClient.ID {
		t.Errorf("act.sub = %v, want %q", actMap["sub"], actorClient.ID)
	}
}

func TestTokenExchange_StampsActorTypeService_ForNonAgentClient(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	subClient, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	actorClient, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	// Default createTEClient leaves IsAgent=false; no flip needed.

	subjectClaims := defaultSubjectClaims(subClient.ID)
	subjectClaims.MayAct = map[string]interface{}{"sub": actorClient.ID}
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	actorClaims := defaultSubjectClaims(actorClient.ID)
	actorClaims.Subject = actorClient.ID
	actorToken := setup.mintSubjectToken(t, actorClaims)

	resp, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ActorToken:       actorToken,
		ActorTokenType:   token.TokenTypeAccessToken,
		ClientID:         actorClient.ID,
		ClientSecret:     actorSecret,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	claims := parseClaims(t, resp.AccessToken)
	actMap, ok := claims["act"].(map[string]any)
	if !ok {
		t.Fatalf("act missing or wrong type: %T", claims["act"])
	}
	if actMap["actor_type"] != "service" {
		t.Errorf("act.actor_type = %v, want service", actMap["actor_type"])
	}
}

// TestTokenExchange_PreservesInnerHopActorType — an incoming subject token
// already carries an act chain whose inner hop has actor_type=agent. After
// exchange, the outermost new hop has its own stamped actor_type and the
// inner hop is unchanged (RFC 8693 §4.1 ¶6 — only the outermost actor is
// authoritative).
func TestTokenExchange_PreservesInnerHopActorType(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	subClient, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	actorClient, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	// Outer acting client is a service; inner pre-existing hop claims agent.

	subjectClaims := defaultSubjectClaims(subClient.ID)
	subjectClaims.Act = token.ActClaimToMap(&token.ActClaim{
		Sub:    "prior-agent",
		Extras: map[string]interface{}{"actor_type": "agent"},
	})
	subjectClaims.MayAct = map[string]interface{}{"sub": actorClient.ID}
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	actorClaims := defaultSubjectClaims(actorClient.ID)
	actorClaims.Subject = actorClient.ID
	actorToken := setup.mintSubjectToken(t, actorClaims)

	resp, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ActorToken:       actorToken,
		ActorTokenType:   token.TokenTypeAccessToken,
		ClientID:         actorClient.ID,
		ClientSecret:     actorSecret,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	claims := parseClaims(t, resp.AccessToken)
	outer, ok := claims["act"].(map[string]any)
	if !ok {
		t.Fatalf("act missing or wrong type: %T", claims["act"])
	}
	if outer["actor_type"] != "service" {
		t.Errorf("outer actor_type = %v, want service", outer["actor_type"])
	}
	if outer["sub"] != actorClient.ID {
		t.Errorf("outer sub = %v, want %q", outer["sub"], actorClient.ID)
	}

	inner, ok := outer["act"].(map[string]any)
	if !ok {
		t.Fatalf("inner act missing or wrong type: %T", outer["act"])
	}
	if inner["sub"] != "prior-agent" {
		t.Errorf("inner sub = %v, want prior-agent", inner["sub"])
	}
	if inner["actor_type"] != "agent" {
		t.Errorf("inner actor_type = %v, want agent (unchanged)", inner["actor_type"])
	}
}

// TestTokenExchange_NoActorToken_NoNewHop — self-exchange without an actor
// token preserves existing act as-is and does not stamp a new actor_type.
// Also the laundering-prevention path: chain is passed through, not
// rewritten.
func TestTokenExchange_NoActorToken_NoNewHop(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	c, secret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	subjectClaims := defaultSubjectClaims(c.ID)
	subjectClaims.Act = token.ActClaimToMap(&token.ActClaim{
		Sub:    "agent-1",
		Extras: map[string]interface{}{"actor_type": "agent"},
	})
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	resp, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ClientID:         c.ID,
		ClientSecret:     secret,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	claims := parseClaims(t, resp.AccessToken)
	actMap, ok := claims["act"].(map[string]any)
	if !ok {
		t.Fatalf("act missing or wrong type: %T", claims["act"])
	}
	if actMap["sub"] != "agent-1" {
		t.Errorf("act.sub = %v, want agent-1 (unchanged)", actMap["sub"])
	}
	if actMap["actor_type"] != "agent" {
		t.Errorf("act.actor_type = %v, want agent (from subject token, unchanged)", actMap["actor_type"])
	}
	// No nested act was present in the subject token and none should have
	// been added.
	if _, nested := actMap["act"]; nested {
		t.Errorf("unexpected nested act: %v", actMap["act"])
	}
}

// TestTokenExchange_DoesNotStampNonIdentityClaims pins the RFC 8693 §4.1 ¶2
// invariant: authserver never stamps exp/nbf/aud/iat/jti inside an act hop.
func TestTokenExchange_DoesNotStampNonIdentityClaims(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	subClient, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	actorClient, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	subjectClaims := defaultSubjectClaims(subClient.ID)
	subjectClaims.MayAct = map[string]interface{}{"sub": actorClient.ID}
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	actorClaims := defaultSubjectClaims(actorClient.ID)
	actorClaims.Subject = actorClient.ID
	actorToken := setup.mintSubjectToken(t, actorClaims)

	resp, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ActorToken:       actorToken,
		ActorTokenType:   token.TokenTypeAccessToken,
		ClientID:         actorClient.ID,
		ClientSecret:     actorSecret,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	claims := parseClaims(t, resp.AccessToken)
	actMap, ok := claims["act"].(map[string]any)
	if !ok {
		t.Fatalf("act missing or wrong type: %T", claims["act"])
	}
	// Every key the outer hop carries must be one of the permitted
	// identity fields. sub/actor_type always; act only if nested.
	permitted := map[string]bool{"sub": true, "act": true, "actor_type": true}
	for k := range actMap {
		if !permitted[k] {
			t.Errorf("unexpected key %q in act hop (stamping non-identity claim?)", k)
		}
	}
	for _, forbidden := range []string{"exp", "nbf", "aud", "iat", "jti"} {
		if _, found := actMap[forbidden]; found {
			t.Errorf("act hop contains forbidden non-identity claim %q", forbidden)
		}
	}
}

// TestTokenExchange_StripsNonIdentityClaimsFromInnerHops pins the
// RFC 8693 §4.1 ¶2 sanitization path: if a subject token somehow carries
// structural/temporal claims inside an inner act hop, the exchange must
// strip them before re-emitting the chain. No-op today (authserver never
// stamps those claims on its own tokens) but load-bearing once federation
// / cross-issuer subject tokens become possible.
func TestTokenExchange_StripsNonIdentityClaimsFromInnerHops(t *testing.T) {
	setup := newTETestSetup(t, services.TokenExchangeConfig{
		AllowSelfExchange: true,
		MaxChainDepth:     5,
		TokenExpiry:       15 * time.Minute,
	})

	subClient, _ := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")
	actorClient, actorSecret := setup.createTEClient(t, []string{token.GrantTypeTokenExchange}, "read write")

	// Subject token whose inner act hop carries forbidden non-identity
	// claims alongside sub. We build the raw map directly rather than via
	// ActClaimToMap so the test exercises the sanitize path on ingestion,
	// not a property of the domain converter.
	subjectClaims := defaultSubjectClaims(subClient.ID)
	subjectClaims.Act = map[string]interface{}{
		"sub": "agent-inner",
		"exp": float64(1234567890),
		"nbf": float64(1234567800),
		"aud": []interface{}{"https://resource.example.com"},
		"iat": float64(1234567800),
		"jti": "inner-jti",
	}
	subjectClaims.MayAct = map[string]interface{}{"sub": actorClient.ID}
	subjectToken := setup.mintSubjectToken(t, subjectClaims)

	actorClaims := defaultSubjectClaims(actorClient.ID)
	actorClaims.Subject = actorClient.ID
	actorToken := setup.mintSubjectToken(t, actorClaims)

	resp, err := setup.svc.Exchange(context.Background(), input.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ActorToken:       actorToken,
		ActorTokenType:   token.TokenTypeAccessToken,
		ClientID:         actorClient.ID,
		ClientSecret:     actorSecret,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	claims := parseClaims(t, resp.AccessToken)
	outer, ok := claims["act"].(map[string]any)
	if !ok {
		t.Fatalf("outer act missing or wrong type: %T", claims["act"])
	}
	inner, ok := outer["act"].(map[string]any)
	if !ok {
		t.Fatalf("inner act missing or wrong type: %T", outer["act"])
	}
	if inner["sub"] != "agent-inner" {
		t.Errorf("inner sub = %v, want agent-inner", inner["sub"])
	}
	for _, forbidden := range []string{"exp", "nbf", "aud", "iat", "jti"} {
		if _, found := inner[forbidden]; found {
			t.Errorf("inner act hop still contains forbidden non-identity claim %q after sanitize", forbidden)
		}
	}
}

