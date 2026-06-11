//go:build integration

package services_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/authplane/authserver/internal/adapters/keyfile"
	"github.com/authplane/authserver/internal/brokerproto"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

const aiIssuer = "https://auth.example.com"

type aiTestSetup struct {
	ccSvc    *services.ClientCredentialsService
	teSvc    *services.TokenExchangeService
	aiSvc    *services.AgentIdentityService
	jwksSvc  *services.JWKSService
	auditSvc *services.AuditService
	h        *testdata.TestHelper
	obs      *observability.Provider
	kp       *crypto.KeyPair
}

func newAITestSetup(t *testing.T) *aiTestSetup {
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

	aiSvc := services.NewAgentIdentityService(stores.Client, obs)

	ccSvc := services.NewClientCredentialsService(
		stores.Client, stores.MachineToken, jwksSvc,
		aiIssuer, time.Hour, obs, auditSvc,
		nil,
	)
	ccSvc.WithAgentIdentity(aiSvc)

	registry := services.NewResourceRegistry(stores.Resource, stores.BrokerProvider, obs)
	mintIssuer := services.NewMintIssuer(jwksSvc, stores.Issuance, aiIssuer, obs)
	bpReg := brokerproto.NewRegistry()
	enc := &teTestEncryptor{}
	brokerIssuer := services.NewBrokerIssuer(stores.BrokerGrant, enc, stores.Issuance, bpReg, obs, auditSvc)
	teSvc := services.NewTokenExchangeService(
		stores.Client, stores.MachineToken, jwksSvc, jwksSvc,
		stores.Revocation, aiIssuer,
		services.TokenExchangeConfig{
			AllowSelfExchange: true,
			MaxChainDepth:     10, // high limit — agent_identity truncation is separate at 8
			TokenExpiry:       time.Hour,
		},
		registry, stores.ConsentGrant, mintIssuer, brokerIssuer,
		obs, auditSvc,
	)
	teSvc.WithAgentIdentity(aiSvc)

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

	return &aiTestSetup{
		ccSvc:    ccSvc,
		teSvc:    teSvc,
		aiSvc:    aiSvc,
		jwksSvc:  jwksSvc,
		auditSvc: auditSvc,
		h:        &testdata.TestHelper{Stores: stores},
		obs:      obs,
		kp:       kp,
	}
}

func (s *aiTestSetup) createAgentClient(t *testing.T, name, description string) *client.Client {
	t.Helper()
	ctx := context.Background()
	secret := crypto.GenerateClientSecret()
	hash, _ := crypto.HashBcrypt(secret)
	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    name,
		SecretHash:              hash,
		RedirectURIs:            []string{"https://localhost/callback"},
		GrantTypes:              []string{"client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_post",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceDCR,
		IsAgent:                 true,
		AgentDescription:        description,
		IssuedAt:                time.Now().UTC(),
		UpdatedAt:               time.Now().UTC(),
	}
	if err := s.h.Stores.Client.Create(ctx, c); err != nil {
		t.Fatalf("create agent client: %v", err)
	}
	// Store the plain secret so we can auth.
	c.SecretHash = secret // temporarily store plain secret for test auth
	return c
}

func (s *aiTestSetup) createRegularClient(t *testing.T) *client.Client {
	t.Helper()
	ctx := context.Background()
	secret := crypto.GenerateClientSecret()
	hash, _ := crypto.HashBcrypt(secret)
	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "regular-client",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://localhost/callback"},
		GrantTypes:              []string{"client_credentials"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_post",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceDCR,
		IsAgent:                 false,
		IssuedAt:                time.Now().UTC(),
		UpdatedAt:               time.Now().UTC(),
	}
	if err := s.h.Stores.Client.Create(ctx, c); err != nil {
		t.Fatalf("create regular client: %v", err)
	}
	c.SecretHash = secret
	return c
}

func (s *aiTestSetup) parseClaims(t *testing.T, tokenStr string) map[string]interface{} {
	t.Helper()
	parsed, err := jwt.ParseSigned(tokenStr, []jose.SignatureAlgorithm{jose.ES256, jose.RS256})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	jwks, err := s.jwksSvc.BuildJWKS(context.Background())
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	kid := parsed.Headers[0].KeyID
	keys := jwks.Key(kid)
	if len(keys) == 0 {
		t.Fatalf("no key for kid %s", kid)
	}
	var raw map[string]interface{}
	if err := parsed.Claims(keys[0].Key, &raw); err != nil {
		t.Fatalf("verify claims: %v", err)
	}
	return raw
}

// TestAgentIdentity_AgentClient_GetsAgentID verifies that a client_credentials
// exchange for an agent client includes agent_id in the AT.
func TestAgentIdentity_AgentClient_GetsAgentID(t *testing.T) {
	s := newAITestSetup(t)
	agentClient := s.createAgentClient(t, "my-agent", "A helpful agent")
	ctx := context.Background()

	resp, err := s.ccSvc.Exchange(ctx, input.ClientCredentialsRequest{
		ClientID:     agentClient.ID,
		ClientSecret: agentClient.SecretHash, // plain secret
		Scope:        "",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	claims := s.parseClaims(t, resp.AccessToken)

	agentID, ok := claims["agent_id"].(string)
	if !ok || agentID == "" {
		t.Fatalf("expected agent_id in claims, got %v", claims["agent_id"])
	}
	if agentID != agentClient.ID {
		t.Errorf("agent_id = %q, want %q", agentID, agentClient.ID)
	}

	// No agent_chain for direct issuance (no delegation).
	if _, ok := claims["agent_chain"]; ok {
		t.Error("expected no agent_chain for direct issuance")
	}
}

// TestAgentIdentity_RegularClient_NoAgentClaims verifies that non-agent clients
// do not get agent_id or agent_chain claims.
func TestAgentIdentity_RegularClient_NoAgentClaims(t *testing.T) {
	s := newAITestSetup(t)
	regularClient := s.createRegularClient(t)
	ctx := context.Background()

	resp, err := s.ccSvc.Exchange(ctx, input.ClientCredentialsRequest{
		ClientID:     regularClient.ID,
		ClientSecret: regularClient.SecretHash,
		Scope:        "",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	claims := s.parseClaims(t, resp.AccessToken)

	if _, ok := claims["agent_id"]; ok {
		t.Error("expected no agent_id for regular client")
	}
	if _, ok := claims["agent_chain"]; ok {
		t.Error("expected no agent_chain for regular client")
	}
}

// TestAgentIdentity_Delegation_BuildsChain verifies that token exchange with
// an agent client builds an agent_chain from the act claim.
func TestAgentIdentity_Delegation_BuildsChain(t *testing.T) {
	s := newAITestSetup(t)
	agentClient := s.createAgentClient(t, "agent-a", "Agent A")
	ctx := context.Background()

	// First, get a machine token for the agent.
	ccResp, err := s.ccSvc.Exchange(ctx, input.ClientCredentialsRequest{
		ClientID:     agentClient.ID,
		ClientSecret: agentClient.SecretHash,
		Scope:        "",
	})
	if err != nil {
		t.Fatalf("cc exchange: %v", err)
	}

	// Now do a self-exchange (delegation scenario with act claim).
	// Mint a subject token with may_act allowing this agent.
	subjectClaims := crypto.AccessTokenClaims{
		Issuer:    aiIssuer,
		Subject:   "user-1",
		Audience:  []string{aiIssuer},
		ClientID:  agentClient.ID,
		Scope:     "read write",
		JTI:       crypto.GenerateRandomString(16),
		IssuedAt:  time.Now().Unix(),
		Expiry:    time.Now().Add(time.Hour).Unix(),
		NotBefore: time.Now().Unix(),
	}
	subjectToken, err := crypto.SignAccessToken(s.kp, subjectClaims)
	if err != nil {
		t.Fatalf("sign subject token: %v", err)
	}

	actorToken := ccResp.AccessToken

	teResp, err := s.teSvc.Exchange(ctx, input.TokenExchangeRequest{
		ClientID:         agentClient.ID,
		ClientSecret:     agentClient.SecretHash,
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ActorToken:       actorToken,
		ActorTokenType:   token.TokenTypeAccessToken,
	})
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}

	claims := s.parseClaims(t, teResp.AccessToken)

	// Should have agent_id.
	agentID, ok := claims["agent_id"].(string)
	if !ok || agentID != agentClient.ID {
		t.Errorf("agent_id = %v, want %q", claims["agent_id"], agentClient.ID)
	}

	// Should have agent_chain.
	chainRaw, ok := claims["agent_chain"]
	if !ok {
		t.Fatal("expected agent_chain in claims")
	}
	chainJSON, _ := json.Marshal(chainRaw)
	var chain []string
	json.Unmarshal(chainJSON, &chain)
	if len(chain) != 1 {
		t.Fatalf("agent_chain length = %d, want 1", len(chain))
	}
	if chain[0] != agentClient.ID {
		t.Errorf("agent_chain[0] = %q, want %q", chain[0], agentClient.ID)
	}
}

// TestAgentIdentity_ChainOrder_ShallowToDeep verifies that the agent_chain is
// ordered from shallowest (root) to deepest (acting agent).
func TestAgentIdentity_ChainOrder_ShallowToDeep(t *testing.T) {
	s := newAITestSetup(t)
	agentA := s.createAgentClient(t, "agent-a", "Root agent")
	agentB := s.createAgentClient(t, "agent-b", "Leaf agent")
	ctx := context.Background()

	// Mint a subject token with an act claim from agent-a.
	subjectClaims := crypto.AccessTokenClaims{
		Issuer:    aiIssuer,
		Subject:   "user-1",
		Audience:  []string{aiIssuer},
		ClientID:  agentA.ID,
		Scope:     "read write",
		JTI:       crypto.GenerateRandomString(16),
		IssuedAt:  time.Now().Unix(),
		Expiry:    time.Now().Add(time.Hour).Unix(),
		NotBefore: time.Now().Unix(),
		Act:       token.ActClaimToMap(&token.ActClaim{Sub: agentA.ID}),
		MayAct:    map[string]interface{}{"sub": agentB.ID},
	}
	subjectToken, err := crypto.SignAccessToken(s.kp, subjectClaims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Agent B gets a machine token as actor.
	actorCCResp, err := s.ccSvc.Exchange(ctx, input.ClientCredentialsRequest{
		ClientID: agentB.ID, ClientSecret: agentB.SecretHash,
	})
	if err != nil {
		t.Fatalf("cc exchange: %v", err)
	}

	teResp, err := s.teSvc.Exchange(ctx, input.TokenExchangeRequest{
		ClientID:         agentB.ID,
		ClientSecret:     agentB.SecretHash,
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
		ActorToken:       actorCCResp.AccessToken,
		ActorTokenType:   token.TokenTypeAccessToken,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	claims := s.parseClaims(t, teResp.AccessToken)
	chainRaw, ok := claims["agent_chain"]
	if !ok {
		t.Fatal("expected agent_chain")
	}
	chainJSON, _ := json.Marshal(chainRaw)
	var chain []string
	json.Unmarshal(chainJSON, &chain)

	// Chain should be [agentA.ID, agentB.ID] (shallow to deep).
	if len(chain) != 2 {
		t.Fatalf("agent_chain length = %d, want 2", len(chain))
	}
	if chain[0] != agentA.ID {
		t.Errorf("chain[0] = %q, want %q (root)", chain[0], agentA.ID)
	}
	if chain[1] != agentB.ID {
		t.Errorf("chain[1] = %q, want %q (leaf)", chain[1], agentB.ID)
	}
}

// TestAgentIdentity_ChainTruncated_AtEight verifies defensive chain truncation
// at the agent_chain level (max 8 entries).
func TestAgentIdentity_ChainTruncated_AtEight(t *testing.T) {
	s := newAITestSetup(t)
	agentClient := s.createAgentClient(t, "agent-truncate", "Test truncation")
	ctx := context.Background()

	// Build a deeply nested act claim (10 levels deep to exceed max of 8).
	// We test AttachClaims directly since the token exchange would reject
	// chains this deep with ErrTokenExchangeChainTooDeep.
	deepAct := &token.ActClaim{Sub: "agent-01"}
	current := deepAct
	for i := 2; i <= 10; i++ {
		inner := &token.ActClaim{Sub: fmt.Sprintf("agent-%02d", i)}
		current.Act = inner
		current = inner
	}

	claims := &crypto.AccessTokenClaims{
		Issuer:    aiIssuer,
		Subject:   "user-1",
		Audience:  []string{aiIssuer},
		ClientID:  agentClient.ID,
		Scope:     "read",
		JTI:       crypto.GenerateRandomString(16),
		IssuedAt:  time.Now().Unix(),
		Expiry:    time.Now().Add(time.Hour).Unix(),
		NotBefore: time.Now().Unix(),
		Act:       token.ActClaimToMap(deepAct),
	}

	err := s.aiSvc.AttachClaims(ctx, claims, agentClient.ID)
	if err != nil {
		t.Fatalf("attach claims: %v", err)
	}

	// Chain should be capped at 8.
	if len(claims.AgentChain) > 8 {
		t.Errorf("agent_chain length = %d, want <= 8", len(claims.AgentChain))
	}
	if len(claims.AgentChain) != 8 {
		t.Errorf("agent_chain length = %d, want exactly 8 (truncated)", len(claims.AgentChain))
	}
}

// TestAgentIdentity_DPoPBound_CNFPreserved verifies that agent claims coexist
// with DPoP cnf.jkt.
func TestAgentIdentity_DPoPBound_CNFPreserved(t *testing.T) {
	s := newAITestSetup(t)
	agentClient := s.createAgentClient(t, "dpop-agent", "DPoP agent")
	ctx := context.Background()

	// Mint a subject token with cnf.jkt (DPoP-bound).
	subjectClaims := crypto.AccessTokenClaims{
		Issuer:    aiIssuer,
		Subject:   "user-1",
		Audience:  []string{aiIssuer},
		ClientID:  agentClient.ID,
		Scope:     "read",
		JTI:       crypto.GenerateRandomString(16),
		IssuedAt:  time.Now().Unix(),
		Expiry:    time.Now().Add(time.Hour).Unix(),
		NotBefore: time.Now().Unix(),
		Cnf:       map[string]interface{}{"jkt": "test-thumbprint-abc"},
	}
	subjectToken, err := crypto.SignAccessToken(s.kp, subjectClaims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Self-exchange (impersonation — no actor token).
	teResp, err := s.teSvc.Exchange(ctx, input.TokenExchangeRequest{
		ClientID:         agentClient.ID,
		ClientSecret:     agentClient.SecretHash,
		SubjectToken:     subjectToken,
		SubjectTokenType: token.TokenTypeAccessToken,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	claims := s.parseClaims(t, teResp.AccessToken)

	// Should have agent_id.
	if agentID, ok := claims["agent_id"].(string); !ok || agentID != agentClient.ID {
		t.Errorf("agent_id = %v, want %q", claims["agent_id"], agentClient.ID)
	}

	// Should still have cnf.
	cnf, ok := claims["cnf"].(map[string]interface{})
	if !ok {
		t.Fatal("expected cnf claim")
	}
	if jkt, ok := cnf["jkt"].(string); !ok || jkt != "test-thumbprint-abc" {
		t.Errorf("cnf.jkt = %v, want test-thumbprint-abc", cnf["jkt"])
	}
}
