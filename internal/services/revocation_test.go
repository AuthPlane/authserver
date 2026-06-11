//go:build integration

package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

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
	revokeSvc := services.NewRevocationService(stores.Token, stores.Client, stores.MachineToken, nil, "", obs, auditSvc, stores.Revocation)
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
