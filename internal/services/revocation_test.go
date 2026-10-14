//go:build integration

package services_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

type revocationTestSetup struct {
	revokeSvc *services.RevocationService
	auditSvc  *services.AuditService
	stores    *testdata.TestHelper
}

func newRevocationTestSetup(t *testing.T) *revocationTestSetup {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	auditSvc := services.NewAuditService(stores.Audit, obs)
	revokeSvc := services.NewRevocationService(stores.Token, stores.Client, stores.MachineToken, nil, staticIssuerForTest(""), obs, auditSvc, stores.Revocation)
	return &revocationTestSetup{
		revokeSvc: revokeSvc,
		auditSvc:  auditSvc,
		stores:    &testdata.TestHelper{Stores: stores},
	}
}

// createClientAndFamily creates a client and a token family with a refresh token.
func (s *revocationTestSetup) createClientAndFamily(t *testing.T, isPublic bool) (*client.Client, string, string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "Revoke Test",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceDCR,
		IssuedAt:                now,
		UpdatedAt:               now,
	}

	var secret string
	if !isPublic {
		secret = "revoke-test-secret"
		hash, _ := crypto.HashBcrypt(secret)
		c.SecretHash = hash
		c.TokenEndpointAuthMethod = "client_secret_basic"
	}

	if err := s.stores.Stores.Client.Create(ctx, c); err != nil {
		t.Fatalf("create client: %v", err)
	}

	// token_families.user_id is FK-enforced.
	testdata.EnsureUser(t, s.stores.Stores.User, "user-42")

	// Create family.
	family := &token.Family{
		ID:        crypto.GenerateRandomString(16),
		ClientID:  c.ID,
		UserID:    "user-42",
		Scope:     "tools/query",
		Resource:  "https://mcp.example.com",
		Status:    token.FamilyActive,
		CreatedAt: now,
	}
	if err := s.stores.Stores.Token.CreateFamily(ctx, family); err != nil {
		t.Fatalf("create family: %v", err)
	}

	// Create refresh token.
	refreshPlain := crypto.GenerateRandomString(32)
	rt := &token.RefreshToken{
		ID:        crypto.GenerateRandomString(16),
		FamilyID:  family.ID,
		TokenHash: crypto.HashSHA256(refreshPlain),
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}
	if err := s.stores.Stores.Token.CreateRefreshToken(ctx, rt); err != nil {
		t.Fatalf("create rt: %v", err)
	}

	return c, secret, refreshPlain
}

func TestRevocation_RevokeRefreshToken_FamilyRevoked(t *testing.T) {
	setup := newRevocationTestSetup(t)
	c, _, refreshPlain := setup.createClientAndFamily(t, true)

	err := setup.revokeSvc.RevokeToken(context.Background(), input.RevokeRequest{
		Token:    refreshPlain,
		ClientID: c.ID,
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Verify family is revoked.
	rtHash := crypto.HashSHA256(refreshPlain)
	rt, _ := setup.stores.Stores.Token.GetRefreshTokenByHash(context.Background(), rtHash)
	family, _ := setup.stores.Stores.Token.GetFamily(context.Background(), rt.FamilyID)
	if family.IsActive() {
		t.Error("family should be revoked")
	}

	// Matrix: 15.3 — upgraded from ⚠️: token.revoked audit event recorded
	events, err := setup.auditSvc.Query(context.Background(), output.AuditFilter{
		Action: string(audit.ActionTokenRevoked),
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(events) < 1 {
		t.Error("expected at least 1 token.revoked audit event")
	}
	// Matrix: 15.9 — upgraded from ⚠️: audit record includes client_id
	if events[0].ClientID == "" {
		t.Error("audit client_id should be non-empty on revocation event")
	}
}

func TestRevocation_UnknownToken_NoError(t *testing.T) {
	setup := newRevocationTestSetup(t)
	c, _, _ := setup.createClientAndFamily(t, true)

	err := setup.revokeSvc.RevokeToken(context.Background(), input.RevokeRequest{
		Token:    "unknown-token-value",
		ClientID: c.ID,
	})
	if err != nil {
		t.Fatalf("expected no error for unknown token, got: %v", err)
	}
}

func TestRevocation_AlreadyRevoked_NoError(t *testing.T) {
	setup := newRevocationTestSetup(t)
	c, _, refreshPlain := setup.createClientAndFamily(t, true)

	// Revoke once.
	if err := setup.revokeSvc.RevokeToken(context.Background(), input.RevokeRequest{
		Token:    refreshPlain,
		ClientID: c.ID,
	}); err != nil {
		t.Fatalf("first revoke: %v", err)
	}

	// Revoke again — should still succeed.
	if err := setup.revokeSvc.RevokeToken(context.Background(), input.RevokeRequest{
		Token:    refreshPlain,
		ClientID: c.ID,
	}); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
}

func TestRevocation_WrongClient_NoRevocation(t *testing.T) {
	setup := newRevocationTestSetup(t)
	_, _, refreshPlain := setup.createClientAndFamily(t, true)
	ctx := context.Background()

	// Create a different client.
	now := time.Now().UTC()
	other := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "Other Client",
		RedirectURIs:            []string{"https://other.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceDCR,
		IssuedAt:                now,
		UpdatedAt:               now,
	}
	if err := setup.stores.Stores.Client.Create(ctx, other); err != nil {
		t.Fatalf("create other client: %v", err)
	}

	// Try to revoke with wrong client.
	err := setup.revokeSvc.RevokeToken(ctx, input.RevokeRequest{
		Token:    refreshPlain,
		ClientID: other.ID,
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Family should still be active.
	rtHash := crypto.HashSHA256(refreshPlain)
	rt, _ := setup.stores.Stores.Token.GetRefreshTokenByHash(ctx, rtHash)
	family, _ := setup.stores.Stores.Token.GetFamily(ctx, rt.FamilyID)
	if !family.IsActive() {
		t.Error("family should still be active — wrong client should not revoke")
	}
}

func TestRevocation_ConfidentialClientAuthRequired(t *testing.T) {
	setup := newRevocationTestSetup(t)
	c, _, refreshPlain := setup.createClientAndFamily(t, false)

	// Try without secret.
	err := setup.revokeSvc.RevokeToken(context.Background(), input.RevokeRequest{
		Token:    refreshPlain,
		ClientID: c.ID,
	})
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("expected ErrInvalidClient, got: %v", err)
	}
}

// Matrix: 4.1 — upgraded from ⚠️: revoke access token (not just refresh)
func TestRevocation_RevokeAccessToken_Returns200(t *testing.T) {
	setup := newRevocationTestSetup(t)
	c, _, _ := setup.createClientAndFamily(t, true)

	// Revoking an unknown token (access tokens are JWTs, not stored) → 200 OK.
	// Per RFC 7009, the server MUST respond with 200 even for unknown tokens.
	err := setup.revokeSvc.RevokeToken(context.Background(), input.RevokeRequest{
		Token:    "some-access-token-value",
		ClientID: c.ID,
	})
	if err != nil {
		t.Fatalf("expected no error for access token revocation, got: %v", err)
	}
}

// Matrix: 4.6 — upgraded from ⚠️: public client can revoke without auth
func TestRevocation_PublicClientNoSecret_Succeeds(t *testing.T) {
	setup := newRevocationTestSetup(t)
	c, _, refreshPlain := setup.createClientAndFamily(t, true)

	// Public client revocation without secret should work.
	err := setup.revokeSvc.RevokeToken(context.Background(), input.RevokeRequest{
		Token:    refreshPlain,
		ClientID: c.ID,
	})
	if err != nil {
		t.Fatalf("public client revocation should succeed: %v", err)
	}
}

// TestRevocation_SuspendedPublicClient_NoStatusLeak pins that a suspended
// public client gets the ordinary RFC 7009 success, not invalid_client.
//
// A public client_id travels in the authorize URL and in browser redirects, so
// distinguishing "suspended" from "active" here would hand anyone an anonymous
// client-status oracle. The suspension still bites: nothing is revoked.
func TestRevocation_SuspendedPublicClient_NoStatusLeak(t *testing.T) {
	setup := newRevocationTestSetup(t)
	ctx := context.Background()
	c, _, refreshPlain := setup.createClientAndFamily(t, true)

	c.Status = client.StatusSuspended
	if err := setup.stores.Stores.Client.Update(ctx, c); err != nil {
		t.Fatalf("suspend client: %v", err)
	}

	err := setup.revokeSvc.RevokeToken(ctx, input.RevokeRequest{
		Token:    refreshPlain,
		ClientID: c.ID,
	})
	if err != nil {
		t.Fatalf("suspended public client must not surface an error: %v", err)
	}

	// Nothing was revoked — the refusal is silent, not cosmetic.
	rt, err := setup.stores.Stores.Token.GetRefreshTokenByHash(ctx, crypto.HashSHA256(refreshPlain))
	if err != nil {
		t.Fatalf("get refresh token: %v", err)
	}
	family, err := setup.stores.Stores.Token.GetFamily(ctx, rt.FamilyID)
	if err != nil {
		t.Fatalf("get family: %v", err)
	}
	if !family.IsActive() {
		t.Error("a suspended client must not be able to revoke")
	}
}

// TestRevocation_SuspendedConfidentialClient_InvalidClient covers the other
// half: a caller that proved it holds the secret learns the client's status,
// because it already knows it. The status check runs after the secret check so
// the two refusals are not separable by timing.
func TestRevocation_SuspendedConfidentialClient_InvalidClient(t *testing.T) {
	setup := newRevocationTestSetup(t)
	ctx := context.Background()
	c, secret, refreshPlain := setup.createClientAndFamily(t, false)

	c.Status = client.StatusSuspended
	if err := setup.stores.Stores.Client.Update(ctx, c); err != nil {
		t.Fatalf("suspend client: %v", err)
	}

	err := setup.revokeSvc.RevokeToken(ctx, input.RevokeRequest{
		Token:        refreshPlain,
		ClientID:     c.ID,
		ClientSecret: secret,
	})
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Fatalf("got %v, want ErrInvalidClient", err)
	}

	// A wrong secret is refused identically, so the response cannot be read as
	// a statement about the client's status.
	err = setup.revokeSvc.RevokeToken(ctx, input.RevokeRequest{
		Token:        refreshPlain,
		ClientID:     c.ID,
		ClientSecret: "wrong-secret",
	})
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Fatalf("wrong secret: got %v, want ErrInvalidClient", err)
	}
}

// accessTokenRevokeSetup builds a revocation service that can verify JWT
// access tokens, over stores the test may wrap.
type accessTokenRevokeSetup struct {
	svc      *services.RevocationService
	auditSvc *services.AuditService
	stores   *testdata.TestHelper
	kp       *crypto.KeyPair
	clientID string
	secret   string
}

func newAccessTokenRevokeSetup(t *testing.T, wrapRev func(output.RevocationStore) output.RevocationStore) *accessTokenRevokeSetup {
	t.Helper()
	base := newRevocationTestSetup(t)
	c, secret, _ := base.createClientAndFamily(t, false)
	kp, err := crypto.GenerateKeyPair("ES256", "revoke-kid")
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	rev := output.RevocationStore(base.stores.Stores.Revocation)
	if wrapRev != nil {
		rev = wrapRev(rev)
	}
	st := base.stores.Stores
	svc := services.NewRevocationService(st.Token, st.Client, st.MachineToken, &mockJWKSBuild{kp: kp},
		staticIssuerForTest(testIssuer), testObs(), base.auditSvc, rev)
	svc.WithIssuanceStore(st.Issuance)
	return &accessTokenRevokeSetup{svc: svc, auditSvc: base.auditSvc, stores: base.stores, kp: kp, clientID: c.ID, secret: secret}
}

func (s *accessTokenRevokeSetup) revoke(t *testing.T, tok string) error {
	t.Helper()
	return s.svc.RevokeToken(context.Background(), input.RevokeRequest{Token: tok, ClientID: s.clientID, ClientSecret: s.secret})
}

func (s *accessTokenRevokeSetup) revokedEvents(t *testing.T) int {
	t.Helper()
	events, err := s.auditSvc.Query(context.Background(), output.AuditFilter{Action: string(audit.ActionTokenRevoked), Limit: 10})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	return len(events)
}

// An access token with neither a machine-token nor an issuance row is
// revoked through the denylist until its own exp, and a second revoke of
// the same token records nothing new.
func TestRevocation_AccessToken_DenylistedOnceAndAuditedOnce(t *testing.T) {
	s := newAccessTokenRevokeSetup(t, nil)
	claims := validClaims()
	claims.ClientID = s.clientID
	tok := signTestToken(t, s.kp, claims)

	if err := s.revoke(t, tok); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked, err := s.stores.Stores.Revocation.IsRevoked(context.Background(), claims.JTI); err != nil || !revoked {
		t.Fatalf("IsRevoked = %v, %v; want the token on the denylist", revoked, err)
	}
	if n := s.revokedEvents(t); n != 1 {
		t.Fatalf("token.revoked events = %d, want 1", n)
	}

	if err := s.revoke(t, tok); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	if n := s.revokedEvents(t); n != 1 {
		t.Errorf("token.revoked events after a second revoke = %d, want still 1: nothing new was revoked", n)
	}
}

type failingRevokeJTI struct{ output.RevocationStore }

func (failingRevokeJTI) RevokeJTI(context.Context, string, time.Time) error {
	return errors.New("revocation store unavailable")
}

// A revocation the store could not record is an error, not the RFC 7009
// 200: the token is still valid and the client must not be told otherwise.
func TestRevocation_AccessToken_StoreFailure_ReturnsError(t *testing.T) {
	s := newAccessTokenRevokeSetup(t, func(r output.RevocationStore) output.RevocationStore { return failingRevokeJTI{r} })
	claims := validClaims()
	claims.ClientID = s.clientID

	err := s.revoke(t, signTestToken(t, s.kp, claims))
	if err == nil || errors.Is(err, domain.ErrInvalidClient) {
		t.Fatalf("err = %v, want a store error", err)
	}
	if n := s.revokedEvents(t); n != 0 {
		t.Errorf("token.revoked events = %d, want 0 for a revocation that did not happen", n)
	}
}

// Another client's access token is left alone.
func TestRevocation_AccessToken_ForeignClient_NotRevoked(t *testing.T) {
	s := newAccessTokenRevokeSetup(t, nil)
	claims := validClaims()
	claims.ClientID = "some-other-client"

	if err := s.revoke(t, signTestToken(t, s.kp, claims)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked, err := s.stores.Stores.Revocation.IsRevoked(context.Background(), claims.JTI); err != nil || revoked {
		t.Errorf("IsRevoked = %v, %v; want another client's token untouched", revoked, err)
	}
	if n := s.revokedEvents(t); n != 0 {
		t.Errorf("token.revoked events = %d, want 0", n)
	}
}

type failingRevokeFamily struct{ output.TokenStore }

func (failingRevokeFamily) RevokeFamily(context.Context, string) (bool, error) {
	return false, errors.New("token store unavailable")
}

// A refresh-token family the store could not revoke is an error too.
func TestRevocation_RefreshToken_StoreFailure_ReturnsError(t *testing.T) {
	base := newRevocationTestSetup(t)
	c, _, refreshPlain := base.createClientAndFamily(t, true)
	st := base.stores.Stores
	svc := services.NewRevocationService(failingRevokeFamily{st.Token}, st.Client, st.MachineToken, nil,
		staticIssuerForTest(""), testObs(), base.auditSvc, st.Revocation)

	err := svc.RevokeToken(context.Background(), input.RevokeRequest{Token: refreshPlain, ClientID: c.ID})
	if err == nil || errors.Is(err, domain.ErrInvalidClient) {
		t.Fatalf("err = %v, want a store error", err)
	}
}

// A token minted for a registered resource has an issuance row, whatever
// grant minted it; the revoke sets its revoked_at, which the post-mint
// re-check in token exchange and the admin issuance list read.
func TestRevocation_AccessToken_IssuanceRowRevoked(t *testing.T) {
	s := newAccessTokenRevokeSetup(t, nil)
	claims := validClaims()
	claims.ClientID = s.clientID
	testdata.CreateMintResource(t, s.stores.Stores, "res-revoke", "revoke-res", "https://revoke-res.test")
	testdata.EnsureUser(t, s.stores.Stores.User, claims.Subject)
	testdata.CreateIssuance(t, s.stores.Stores, claims.JTI, claims.Subject, s.clientID, "res-revoke", s.clientID, "")

	if err := s.revoke(t, signTestToken(t, s.kp, claims)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !testdata.IssuanceRevoked(t, s.stores.Stores, claims.JTI) {
		t.Error("issuance row not revoked")
	}
}

// Revoking a refresh token whose family is already revoked records nothing
// new.
func TestRevocation_RefreshToken_SecondRevokeNotAudited(t *testing.T) {
	setup := newRevocationTestSetup(t)
	c, _, refreshPlain := setup.createClientAndFamily(t, true)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := setup.revokeSvc.RevokeToken(ctx, input.RevokeRequest{Token: refreshPlain, ClientID: c.ID}); err != nil {
			t.Fatalf("revoke %d: %v", i+1, err)
		}
	}
	events, err := setup.auditSvc.Query(ctx, output.AuditFilter{Action: string(audit.ActionTokenRevoked), Limit: 10})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("token.revoked events = %d, want 1 across two revokes of the same family", len(events))
	}
}

// failOnceRevokeByFamily fails its first RevokeByFamily and passes the rest
// through.
type failOnceRevokeByFamily struct {
	output.RevocationStore
	calls *int
}

func (f failOnceRevokeByFamily) RevokeByFamily(ctx context.Context, familyID string) error {
	*f.calls++
	if *f.calls == 1 {
		return errors.New("revocation store unavailable")
	}
	return f.RevocationStore.RevokeByFamily(ctx, familyID)
}

// The family row commits before the denylist write. When that write fails,
// the client gets an error and retries; the retry must denylist the family's
// access tokens, and the revocation must be audited exactly once across the
// two calls even though the retry finds the family already revoked.
func TestRevocation_RefreshToken_DenylistFailure_RetryCompletesAndAuditsOnce(t *testing.T) {
	base := newRevocationTestSetup(t)
	c, _, refreshPlain := base.createClientAndFamily(t, true)
	st := base.stores.Stores
	ctx := context.Background()

	rt, err := st.Token.GetRefreshTokenByHash(ctx, crypto.HashSHA256(refreshPlain))
	if err != nil {
		t.Fatalf("get refresh token: %v", err)
	}
	if err := st.Revocation.TrackJTI(ctx, "jti-in-family", rt.FamilyID, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("track: %v", err)
	}

	calls := 0
	svc := services.NewRevocationService(st.Token, st.Client, st.MachineToken, nil,
		staticIssuerForTest(""), testObs(), base.auditSvc, failOnceRevokeByFamily{st.Revocation, &calls})
	req := input.RevokeRequest{Token: refreshPlain, ClientID: c.ID}

	if err := svc.RevokeToken(ctx, req); err == nil {
		t.Fatal("first revoke: want an error from the failed denylist write")
	}
	if err := svc.RevokeToken(ctx, req); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if revoked, err := st.Revocation.IsRevoked(ctx, "jti-in-family"); err != nil || !revoked {
		t.Errorf("IsRevoked = %v, %v; want the family's access token denylisted by the retry", revoked, err)
	}
	events, err := base.auditSvc.Query(ctx, output.AuditFilter{Action: string(audit.ActionTokenRevoked), Limit: 10})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("token.revoked events = %d, want 1", len(events))
	}
}

// failOnceIssuanceRevoke fails its first Revoke and passes the rest through.
type failOnceIssuanceRevoke struct {
	output.IssuanceStore
	calls *int
}

func (f failOnceIssuanceRevoke) Revoke(ctx context.Context, id string) error {
	*f.calls++
	if *f.calls == 1 {
		return errors.New("issuance store unavailable")
	}
	return f.IssuanceStore.Revoke(ctx, id)
}

// Each record commits on its own. When the machine-token write lands and the
// issuance write fails, the token is already refused, so that call audits
// the revocation even though it answers with an error; the retry completes
// the remaining records and audits nothing new.
func TestRevocation_AccessToken_PartialWrite_AuditedOnceAndCompletedOnRetry(t *testing.T) {
	s := newAccessTokenRevokeSetup(t, nil)
	st := s.stores.Stores
	ctx := context.Background()
	claims := validClaims()
	claims.ClientID = s.clientID
	now := time.Now().UTC()
	if err := st.MachineToken.Save(ctx, token.MachineToken{JTI: claims.JTI, ClientID: s.clientID, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatalf("save machine token: %v", err)
	}
	testdata.CreateMintResource(t, st, "res-partial", "partial-res", "https://partial-res.test")
	testdata.EnsureUser(t, st.User, claims.Subject)
	testdata.CreateIssuance(t, st, claims.JTI, claims.Subject, s.clientID, "res-partial", s.clientID, "")

	calls := 0
	svc := services.NewRevocationService(st.Token, st.Client, st.MachineToken, &mockJWKSBuild{kp: s.kp},
		staticIssuerForTest(testIssuer), testObs(), s.auditSvc, st.Revocation)
	svc.WithIssuanceStore(failOnceIssuanceRevoke{st.Issuance, &calls})
	req := input.RevokeRequest{Token: signTestToken(t, s.kp, claims), ClientID: s.clientID, ClientSecret: s.secret}

	if err := svc.RevokeToken(ctx, req); err == nil {
		t.Fatal("first revoke: want an error from the failed issuance write")
	}
	events, err := s.auditSvc.Query(ctx, output.AuditFilter{Action: string(audit.ActionTokenRevoked), Limit: 10})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(events) != 1 || !strings.Contains(events[0].Detail, "revoked_in=machine_token") {
		t.Fatalf("after the failed call: audit = %+v, want one row naming machine_token", events)
	}

	if err := svc.RevokeToken(ctx, req); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !testdata.IssuanceRevoked(t, st, claims.JTI) {
		t.Error("issuance row not revoked by the retry")
	}
	if revoked, err := st.Revocation.IsRevoked(ctx, claims.JTI); err != nil || !revoked {
		t.Errorf("IsRevoked = %v, %v; want the retry to denylist the token", revoked, err)
	}
	if events, _ = s.auditSvc.Query(ctx, output.AuditFilter{Action: string(audit.ActionTokenRevoked), Limit: 10}); len(events) != 1 {
		t.Errorf("token.revoked events after the retry = %d, want still 1", len(events))
	}
}

// A token already revoked by another action (here the admin issuance
// revoke, which audits itself) gets its remaining records completed but no
// second token.revoked row.
func TestRevocation_AccessToken_RevokedElsewhere_CompletedNotAudited(t *testing.T) {
	s := newAccessTokenRevokeSetup(t, nil)
	st := s.stores.Stores
	ctx := context.Background()
	claims := validClaims()
	claims.ClientID = s.clientID
	testdata.CreateMintResource(t, st, "res-elsewhere", "elsewhere-res", "https://elsewhere-res.test")
	testdata.EnsureUser(t, st.User, claims.Subject)
	testdata.CreateIssuance(t, st, claims.JTI, claims.Subject, s.clientID, "res-elsewhere", s.clientID, "")
	testdata.RevokeIssuance(t, st, claims.JTI)

	if err := s.revoke(t, signTestToken(t, s.kp, claims)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked, err := st.Revocation.IsRevoked(ctx, claims.JTI); err != nil || !revoked {
		t.Errorf("IsRevoked = %v, %v; want the remaining denylist record written", revoked, err)
	}
	if n := s.revokedEvents(t); n != 0 {
		t.Errorf("token.revoked events = %d, want 0: the token was already revoked", n)
	}
}

// The metric reason says whether the call revoked a machine-token row.
func TestRevocation_AccessToken_MetricReason(t *testing.T) {
	s := newAccessTokenRevokeSetup(t, nil)
	st := s.stores.Stores
	ctx := context.Background()
	obs := testObs()
	m := newReuseMetrics(t, obs)
	svc := services.NewRevocationService(st.Token, st.Client, st.MachineToken, &mockJWKSBuild{kp: s.kp},
		staticIssuerForTest(testIssuer), obs, s.auditSvc, st.Revocation)

	machine := validClaims()
	machine.ClientID = s.clientID
	now := time.Now().UTC()
	if err := st.MachineToken.Save(ctx, token.MachineToken{JTI: machine.JTI, ClientID: s.clientID, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatalf("save machine token: %v", err)
	}
	plain := validClaims()
	plain.ClientID = s.clientID

	for _, c := range []crypto.AccessTokenClaims{machine, plain} {
		if err := svc.RevokeToken(ctx, input.RevokeRequest{Token: signTestToken(t, s.kp, c), ClientID: s.clientID, ClientSecret: s.secret}); err != nil {
			t.Fatalf("revoke %s: %v", c.JTI, err)
		}
	}
	if got := m.valueWith(t, mRevoked, []attribute.KeyValue{attribute.String("reason", "explicit_machine")}); got != 1 {
		t.Errorf("explicit_machine = %d, want 1", got)
	}
	if got := m.valueWith(t, mRevoked, []attribute.KeyValue{attribute.String("reason", "explicit_access")}); got != 1 {
		t.Errorf("explicit_access = %d, want 1", got)
	}
}
