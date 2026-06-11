package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// --- Mock JWKSSigningKeyProvider ---

type mockSigningKeyProvider struct {
	key *output.SigningKey
	err error
}

func (m *mockSigningKeyProvider) GetSigningKey(_ context.Context) (*output.SigningKey, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.key, nil
}

func newTestSigningKey(t *testing.T) *output.SigningKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	return &output.SigningKey{
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		Algorithm:  "ES256",
		KeyID:      "test-kid",
	}
}

// --- Fixtures ---

const testIssuer = "https://auth.example.com"

func newMintIssuerForTest(t *testing.T, keys JWKSSigningKeyProvider, issuances output.IssuanceStore) *MintIssuer {
	t.Helper()
	return NewMintIssuer(keys, issuances, testIssuer, observability.NewNoop())
}

func mintBaseRequest() IssueRequest {
	return IssueRequest{
		SubjectUserID: "user-42",
		ActorClientID: "mcp-client",
		Scopes:        []string{"tools/query", "memory/read"},
		Expiry:        time.Now().UTC().Add(15 * time.Minute),
	}
}

func decodeMintToken(t *testing.T, raw string, key *output.SigningKey) *crypto.AccessTokenClaims {
	t.Helper()
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       key.PublicKey,
		KeyID:     key.KeyID,
		Algorithm: key.Algorithm,
		Use:       "sig",
	}}}
	claims, err := crypto.VerifyAccessToken(raw, &jwks)
	if err != nil {
		t.Fatalf("verify mint token: %v", err)
	}
	return claims
}

// --- Tests ---

func TestMintIssuer_Kind(t *testing.T) {
	mi := newMintIssuerForTest(t, &mockSigningKeyProvider{key: newTestSigningKey(t)}, &mockIssuanceStore{})
	if got := mi.Kind(); got != resource.BackendMint {
		t.Errorf("Kind() = %q, want %q", got, resource.BackendMint)
	}
}

func TestMintIssuer_SatisfiesIssuerInterface(t *testing.T) {
	// Compile-time substitution gate. Drift in MintIssuer's method set
	// would fail to compile here.
	var _ Issuer = (*MintIssuer)(nil)
}

func TestMintIssuer_Issue_BuildsExpectedClaims(t *testing.T) {
	key := newTestSigningKey(t)
	store := &mockIssuanceStore{}
	mi := newMintIssuerForTest(t, &mockSigningKeyProvider{key: key}, store)

	res := &resource.Resource{
		ID:          "res-mcp",
		Slug:        "mcp",
		URI:         "https://mcp.example.com",
		BackendKind: resource.BackendMint,
	}
	req := mintBaseRequest()
	req.Resource = res
	req.DPoPJKT = "thumbprint-abc"

	resp, err := mi.Issue(context.Background(), req)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("AccessToken should be non-empty")
	}
	if resp.IssuanceID == "" {
		t.Fatal("IssuanceID should be non-empty")
	}

	claims := decodeMintToken(t, resp.AccessToken, key)
	if claims.Issuer != testIssuer {
		t.Errorf("iss = %q, want %q", claims.Issuer, testIssuer)
	}
	if claims.Subject != "user-42" {
		t.Errorf("sub = %q, want %q", claims.Subject, "user-42")
	}
	if claims.ClientID != "mcp-client" {
		t.Errorf("client_id = %q, want %q", claims.ClientID, "mcp-client")
	}
	if got := claims.Scope; got != "tools/query memory/read" {
		t.Errorf("scope = %q, want %q", got, "tools/query memory/read")
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != res.URI {
		t.Errorf("aud = %v, want [%q]", claims.Audience, res.URI)
	}
	if claims.JTI == "" {
		t.Error("jti claim is empty")
	}
	if claims.JTI != resp.IssuanceID {
		t.Errorf("response.IssuanceID (%q) must equal claims.JTI (%q)", resp.IssuanceID, claims.JTI)
	}
	if claims.IssuedAt == 0 || claims.Expiry == 0 || claims.NotBefore == 0 {
		t.Errorf("iat/exp/nbf should all be set: iat=%d exp=%d nbf=%d", claims.IssuedAt, claims.Expiry, claims.NotBefore)
	}
	if claims.NotBefore != claims.IssuedAt {
		t.Errorf("nbf should default to iat when not overridden: nbf=%d iat=%d", claims.NotBefore, claims.IssuedAt)
	}
	if claims.Cnf == nil || claims.Cnf["jkt"] != "thumbprint-abc" {
		t.Errorf("cnf.jkt missing or wrong: %v", claims.Cnf)
	}

	if store.insertSeen == nil {
		t.Fatal("expected issuance to be inserted")
	}
	got := store.insertSeen
	if got.ID != claims.JTI || got.JTI != claims.JTI {
		t.Errorf("issuance ID/JTI mismatch: id=%q jti=%q claims.jti=%q", got.ID, got.JTI, claims.JTI)
	}
	if got.BackendKind != resource.BackendMint {
		t.Errorf("issuance.BackendKind = %q, want %q", got.BackendKind, resource.BackendMint)
	}
	if !got.Revocable {
		t.Error("mint issuance must be marked revocable")
	}
	if got.ResourceID != res.ID {
		t.Errorf("issuance.ResourceID = %q, want %q", got.ResourceID, res.ID)
	}
	if got.DPoPJKT != "thumbprint-abc" {
		t.Errorf("issuance.DPoPJKT = %q, want %q", got.DPoPJKT, "thumbprint-abc")
	}
	if got.IssuedAt.Unix() != claims.IssuedAt {
		t.Errorf("issuance.IssuedAt %v should match claims.iat %d", got.IssuedAt, claims.IssuedAt)
	}
	if got.ExpiresAt.Unix() != claims.Expiry {
		t.Errorf("issuance.ExpiresAt %v should match claims.exp %d", got.ExpiresAt, claims.Expiry)
	}
}

func TestMintIssuer_Issue_NoResource_AudienceIsIssuer(t *testing.T) {
	key := newTestSigningKey(t)
	mi := newMintIssuerForTest(t, &mockSigningKeyProvider{key: key}, &mockIssuanceStore{})

	resp, err := mi.Issue(context.Background(), mintBaseRequest())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	claims := decodeMintToken(t, resp.AccessToken, key)
	if len(claims.Audience) != 1 || claims.Audience[0] != testIssuer {
		t.Errorf("aud fallback = %v, want [%q]", claims.Audience, testIssuer)
	}
}

func TestMintIssuer_Issue_AudienceOverride_TakesPrecedence(t *testing.T) {
	key := newTestSigningKey(t)
	mi := newMintIssuerForTest(t, &mockSigningKeyProvider{key: key}, &mockIssuanceStore{})

	res := &resource.Resource{ID: "res-x", Slug: "x", URI: "https://x.example.com", BackendKind: resource.BackendMint}
	req := mintBaseRequest()
	req.Resource = res
	req.Audience = []string{"https://override.example.com"}

	resp, err := mi.Issue(context.Background(), req)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	claims := decodeMintToken(t, resp.AccessToken, key)
	if len(claims.Audience) != 1 || claims.Audience[0] != "https://override.example.com" {
		t.Errorf("aud = %v, want override", claims.Audience)
	}
}

func TestMintIssuer_Issue_NoDPoPJKT_BearerType(t *testing.T) {
	key := newTestSigningKey(t)
	mi := newMintIssuerForTest(t, &mockSigningKeyProvider{key: key}, &mockIssuanceStore{})

	resp, err := mi.Issue(context.Background(), mintBaseRequest())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want %q", resp.TokenType, "Bearer")
	}
	claims := decodeMintToken(t, resp.AccessToken, key)
	if claims.Cnf != nil {
		t.Errorf("cnf should be absent when DPoPJKT is empty, got %v", claims.Cnf)
	}
}

func TestMintIssuer_Issue_DPoPJKT_AttachesCnfAndDPoPType(t *testing.T) {
	key := newTestSigningKey(t)
	mi := newMintIssuerForTest(t, &mockSigningKeyProvider{key: key}, &mockIssuanceStore{})

	req := mintBaseRequest()
	req.DPoPJKT = "thumbprint-xyz"

	resp, err := mi.Issue(context.Background(), req)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if resp.TokenType != "DPoP" {
		t.Errorf("TokenType = %q, want %q", resp.TokenType, "DPoP")
	}
	claims := decodeMintToken(t, resp.AccessToken, key)
	if claims.Cnf == nil {
		t.Fatal("cnf claim missing")
	}
	if claims.Cnf["jkt"] != "thumbprint-xyz" {
		t.Errorf("cnf.jkt = %v, want %q", claims.Cnf["jkt"], "thumbprint-xyz")
	}
}

func TestMintIssuer_Issue_PersistsAgentIdentityToIssuance(t *testing.T) {
	key := newTestSigningKey(t)
	store := &mockIssuanceStore{}
	mi := newMintIssuerForTest(t, &mockSigningKeyProvider{key: key}, store)

	chain := []string{"root-agent", "mid-agent", "leaf-agent"}
	req := mintBaseRequest()
	req.Resource = &resource.Resource{ID: "res-mcp", Slug: "mcp", URI: "https://mcp.example.com", BackendKind: resource.BackendMint}
	req.AgentIdentity = &AgentIdentityClaims{
		AgentID:    "leaf-agent",
		AgentChain: chain,
	}

	resp, err := mi.Issue(context.Background(), req)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	claims := decodeMintToken(t, resp.AccessToken, key)
	if claims.AgentID != "leaf-agent" {
		t.Errorf("claims.agent_id = %q, want %q", claims.AgentID, "leaf-agent")
	}
	if strings.Join(claims.AgentChain, ",") != strings.Join(chain, ",") {
		t.Errorf("claims.agent_chain = %v, want %v", claims.AgentChain, chain)
	}

	if store.insertSeen == nil {
		t.Fatal("issuance not inserted")
	}
	if store.insertSeen.AgentID != "leaf-agent" {
		t.Errorf("issuance.AgentID = %q, want %q", store.insertSeen.AgentID, "leaf-agent")
	}
	if strings.Join(store.insertSeen.AgentChain, ",") != strings.Join(chain, ",") {
		t.Errorf("issuance.AgentChain = %v, want %v", store.insertSeen.AgentChain, chain)
	}
}

func TestMintIssuer_Issue_NoAgentIdentity_EmptyJWTAndIssuanceFields(t *testing.T) {
	key := newTestSigningKey(t)
	store := &mockIssuanceStore{}
	mi := newMintIssuerForTest(t, &mockSigningKeyProvider{key: key}, store)

	res := &resource.Resource{ID: "res-mcp", Slug: "mcp", URI: "https://mcp.example.com", BackendKind: resource.BackendMint}
	req := mintBaseRequest()
	req.Resource = res

	resp, err := mi.Issue(context.Background(), req)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	claims := decodeMintToken(t, resp.AccessToken, key)
	if claims.AgentID != "" {
		t.Errorf("claims.agent_id should be empty without AgentIdentity, got %q", claims.AgentID)
	}
	if len(claims.AgentChain) != 0 {
		t.Errorf("claims.agent_chain should be empty without AgentIdentity, got %v", claims.AgentChain)
	}
	if store.insertSeen == nil {
		t.Fatal("issuance row should be persisted when Resource is supplied")
	}
	if store.insertSeen.AgentID != "" {
		t.Errorf("issuance.AgentID should be empty without AgentIdentity, got %q", store.insertSeen.AgentID)
	}
	if len(store.insertSeen.AgentChain) != 0 {
		t.Errorf("issuance.AgentChain should be empty without AgentIdentity, got %v", store.insertSeen.AgentChain)
	}
}

// TestMintIssuer_Issue_NilResource_SkipsIssuanceInsert pins the
// gap: until  plumbs ResourceRegistry into TokenService, the legacy
// ExchangeCode / RefreshToken callers cannot resolve a *resource.Resource,
// and the issuances.resource_id FK NOT NULL → resources(id) constraint
// rejects empty values. The issuance audit row is intentionally skipped
// for these calls — same observability surface (or lack thereof) as
// previously. The signed JWT remains correct end-to-end.
func TestMintIssuer_Issue_NilResource_SkipsIssuanceInsert(t *testing.T) {
	key := newTestSigningKey(t)
	store := &mockIssuanceStore{}
	mi := newMintIssuerForTest(t, &mockSigningKeyProvider{key: key}, store)

	resp, err := mi.Issue(context.Background(), mintBaseRequest())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("AccessToken should still be issued when Resource is nil")
	}
	if resp.IssuanceID == "" {
		t.Error("IssuanceID (= JTI) should still be returned when Resource is nil")
	}
	if store.insertSeen != nil {
		t.Errorf("issuance row should NOT be inserted when Resource is nil, got %+v", store.insertSeen)
	}
}

func TestMintIssuer_Issue_NotBeforeOverride_Honored(t *testing.T) {
	key := newTestSigningKey(t)
	mi := newMintIssuerForTest(t, &mockSigningKeyProvider{key: key}, &mockIssuanceStore{})

	nbf := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Second)
	req := mintBaseRequest()
	req.NotBefore = nbf

	resp, err := mi.Issue(context.Background(), req)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	claims := decodeMintToken(t, resp.AccessToken, key)
	if claims.NotBefore != nbf.Unix() {
		t.Errorf("nbf = %d, want %d (override)", claims.NotBefore, nbf.Unix())
	}
	if claims.NotBefore >= claims.IssuedAt {
		t.Errorf("nbf override (%d) should be before iat (%d)", claims.NotBefore, claims.IssuedAt)
	}
}

func TestMintIssuer_Issue_PersistsActClaim(t *testing.T) {
	key := newTestSigningKey(t)
	mi := newMintIssuerForTest(t, &mockSigningKeyProvider{key: key}, &mockIssuanceStore{})

	req := mintBaseRequest()
	req.Act = map[string]interface{}{"sub": "delegating-client"}

	resp, err := mi.Issue(context.Background(), req)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	claims := decodeMintToken(t, resp.AccessToken, key)
	if claims.Act == nil || claims.Act["sub"] != "delegating-client" {
		t.Errorf("act = %v, want sub=delegating-client", claims.Act)
	}
}

func TestMintIssuer_Issue_ZeroExpiry_Error(t *testing.T) {
	key := newTestSigningKey(t)
	mi := newMintIssuerForTest(t, &mockSigningKeyProvider{key: key}, &mockIssuanceStore{})

	req := mintBaseRequest()
	req.Expiry = time.Time{}

	resp, err := mi.Issue(context.Background(), req)
	if err == nil {
		t.Fatalf("expected error on zero Expiry, got resp=%+v", resp)
	}
	if resp != nil {
		t.Errorf("expected nil response on error, got %+v", resp)
	}
}

func TestMintIssuer_Issue_SigningKeyError_Wrapped(t *testing.T) {
	sentinel := errors.New("backend explosion")
	mi := newMintIssuerForTest(t,
		&mockSigningKeyProvider{err: sentinel},
		&mockIssuanceStore{},
	)

	resp, err := mi.Issue(context.Background(), mintBaseRequest())
	if resp != nil {
		t.Errorf("expected nil response on signing-key error, got %+v", resp)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected error to wrap sentinel; got %v", err)
	}
}

func TestMintIssuer_Issue_IssuanceInsertError_Wrapped(t *testing.T) {
	key := newTestSigningKey(t)
	sentinel := errors.New("issuances table down")
	store := &mockIssuanceStore{insertErr: sentinel}
	mi := newMintIssuerForTest(t, &mockSigningKeyProvider{key: key}, store)

	req := mintBaseRequest()
	req.Resource = &resource.Resource{ID: "res-mcp", Slug: "mcp", URI: "https://mcp.example.com", BackendKind: resource.BackendMint}

	resp, err := mi.Issue(context.Background(), req)
	if resp != nil {
		t.Errorf("expected nil response on insert error, got %+v", resp)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected error to wrap sentinel; got %v", err)
	}
	if store.insertSeen == nil {
		t.Error("Insert was expected to have been called before erroring")
	}
}
