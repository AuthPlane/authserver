//go:build integration

package services_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/domain/session"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

// --- Admin Service: Transactional Delete Tests ---

func newAdminSetupWithTx(t *testing.T) *adminTestSetup {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	adminSvc := services.NewAdminService(
		stores.Client, stores.User, stores.Token, stores.Audit,
		obs, nil,
		services.WithMachineTokenStore(stores.MachineToken),
		services.WithRevocationStore(stores.Revocation),
		services.WithTransactionManager(stores.TransactionMgr),
	)
	return &adminTestSetup{
		adminSvc: adminSvc,
		stores:   &testdata.TestHelper{Stores: stores},
	}
}

func TestAdmin_DeleteClient_WithTransaction_Atomicity(t *testing.T) {
	setup := newAdminSetupWithTx(t)
	ctx := context.Background()

	c := setup.createTestClient(t)

	// Create an active token family.
	family := &token.Family{
		ID:        crypto.GenerateRandomString(16),
		ClientID:  c.ID,
		UserID:    "tx-delete-user",
		Scope:     "tools/query",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	}
	setup.createTokenFamily(t, ctx, family)

	// Force delete should atomically revoke tokens + delete client.
	if err := setup.adminSvc.DeleteClient(ctx, c.ID, true); err != nil {
		t.Fatalf("force delete: %v", err)
	}

	// Verify client is deleted.
	_, err := setup.stores.Stores.Client.GetByID(ctx, c.ID)
	if err == nil {
		t.Fatal("client should be deleted")
	}

	// token_families.client_id is FK ON DELETE CASCADE, so the
	// family is gone once the parent client is deleted. AdminService still
	// revokes explicitly (audit trail + JTI blacklist) before the delete,
	// but the persisted-row outcome is "removed by cascade", not "row
	// retained with status=revoked". Either signals the tokens are no
	// longer usable; the cascade is the stronger guarantee.
	_, err = setup.stores.Stores.Token.GetFamily(ctx, family.ID)
	if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("expected ErrInvalidGrant after cascade, got: %v", err)
	}
}

func TestAdmin_DeleteUser_WithTransaction_Atomicity(t *testing.T) {
	setup := newAdminSetupWithTx(t)
	ctx := context.Background()

	u, err := setup.adminSvc.CreateUser(ctx, input.CreateUserRequest{
		Email: "tx-delete@example.com", Password: "pass", Role: user.RoleUser,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	family := &token.Family{
		ID:        crypto.GenerateRandomString(16),
		ClientID:  "tx-del-user-client",
		UserID:    u.ID,
		Scope:     "tools/query",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	}
	setup.createTokenFamily(t, ctx, family)

	if err := setup.adminSvc.DeleteUser(ctx, u.ID, true); err != nil {
		t.Fatalf("force delete: %v", err)
	}

	_, err = setup.stores.Stores.User.GetByID(ctx, u.ID)
	if err == nil {
		t.Fatal("user should be deleted")
	}
}

// --- Client Optimistic Locking through Admin Service ---

func TestAdmin_UpdateClient_VersionConflict(t *testing.T) {
	setup := newAdminSetupWithTx(t)
	ctx := context.Background()

	resp, err := setup.adminSvc.CreateClient(ctx, input.CreateClientRequest{
		Name:                    "Conflict Test",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "none",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Update the client directly in the store to bump version.
	c, _ := setup.stores.Stores.Client.GetByID(ctx, resp.Client.ID)
	c.Name = "Sneaky Update"
	c.UpdatedAt = time.Now().UTC()
	if err := setup.stores.Stores.Client.Update(ctx, c); err != nil {
		t.Fatalf("direct update: %v", err)
	}

	// Now admin update should succeed because it re-fetches fresh version.
	newName := "Admin Update"
	_, err = setup.adminSvc.UpdateClient(ctx, resp.Client.ID, input.UpdateClientRequest{
		Name: &newName,
	})
	if err != nil {
		t.Fatalf("admin update should succeed with fresh version: %v", err)
	}
}

// --- Concurrent Client Updates through Admin Service ---

func TestAdmin_ConcurrentClientUpdates(t *testing.T) {
	setup := newAdminSetupWithTx(t)
	ctx := context.Background()

	resp, err := setup.adminSvc.CreateClient(ctx, input.CreateClientRequest{
		Name:                    "Concurrent Target",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "none",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Concurrent suspends — these should all either succeed or fail gracefully.
	const goroutines = 3
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			err := setup.adminSvc.SuspendClient(ctx, resp.Client.ID)
			mu.Lock()
			errs = append(errs, err)
			mu.Unlock()
		}()
	}
	wg.Wait()

	// At least one should succeed.
	var successes int
	for _, err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes < 1 {
		t.Errorf("expected at least 1 success, got 0. Errors: %v", errs)
	}

	// Final state should be suspended.
	got, _ := setup.stores.Stores.Client.GetByID(ctx, resp.Client.ID)
	if got.Status != client.StatusSuspended {
		t.Errorf("status: got %q, want suspended", got.Status)
	}
}

// --- Token Service: Transaction Wiring ---

func newTokenSetupWithTx(t *testing.T) *tokenTestSetup {
	t.Helper()
	setup := newTokenTestSetup(t)
	setup.tokenSvc.WithTokenTransactions(setup.h.Stores.TransactionMgr)
	return setup
}

func TestToken_ExchangeCode_WithTransaction(t *testing.T) {
	setup := newTokenSetupWithTx(t)
	c, sess, code, verifier := setup.createSessionWithCode(t, true)

	resp, err := setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("access token empty")
	}
	if resp.RefreshToken == "" {
		t.Error("refresh token empty")
	}

	// Verify session was consumed (code can't be reused).
	_, err = setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: verifier,
	})
	if err == nil {
		t.Fatal("expected error on code reuse")
	}

	_ = sess // suppress unused warning
}

func TestToken_RefreshWithTransaction_ReuseDetection(t *testing.T) {
	setup := newTokenSetupWithTx(t)
	c, _, code, verifier := setup.createSessionWithCode(t, true)

	// Exchange code for tokens.
	resp, err := setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	// Refresh once — should succeed.
	refreshResp, err := setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: resp.RefreshToken,
		ClientID:     c.ID,
	})
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if refreshResp.RefreshToken == resp.RefreshToken {
		t.Error("refresh token should rotate")
	}

	// Reuse the original (consumed) refresh token — should trigger family revocation.
	_, err = setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: resp.RefreshToken,
		ClientID:     c.ID,
	})
	if err == nil {
		t.Fatal("expected error on refresh token reuse")
	}
	if !errors.Is(err, domain.ErrFamilyRevoked) {
		t.Errorf("expected ErrFamilyRevoked, got %v", err)
	}

	// Even the new token should now fail (entire family revoked).
	_, err = setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: refreshResp.RefreshToken,
		ClientID:     c.ID,
	})
	if err == nil {
		t.Fatal("expected error — family should be revoked")
	}
}

// --- Consent Service: Transaction Wiring ---

func TestConsent_GrantConsent_WithTransaction(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	auditSvc := services.NewAuditService(stores.Audit, obs)
	registry := newTestRegistry(stores)

	const uri = "https://mcp.example.com"
	seedMintResource(t, stores, "mcp-tx", "TX MCP", uri,
		resource.Scope{Name: "tools/query", Description: "Query"},
	)

	consentSvc := services.NewConsentService(
		stores.ConsentGrant, stores.Session, stores.Client, registry, obs, auditSvc,
	)
	consentSvc.WithConsentTransactions(stores.TransactionMgr)

	ctx := context.Background()
	now := time.Now().UTC()

	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "TX Consent Test",
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
	if err := seedUser(ctx, stores, "consent-tx-user"); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	code := crypto.GenerateAuthCode()
	verifier := crypto.GenerateVerifier()
	sess := &session.AuthSession{
		ID:                  crypto.GenerateRandomString(16),
		ClientID:            c.ID,
		UserID:              "consent-tx-user",
		RedirectURI:         "https://app.example.com/callback",
		Scope:               "tools/query",
		Resource:            uri,
		State:               "state-tx",
		CodeHash:            crypto.HashSHA256(code),
		CodeChallenge:       crypto.ComputeS256Challenge(verifier),
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(session.AuthCodeTTL),
		CreatedAt:           now,
	}
	if err := stores.Session.Create(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	result, err := consentSvc.GrantConsent(ctx, input.GrantConsentRequest{
		SessionID:      sess.ID,
		UserID:         "consent-tx-user",
		ApprovedScopes: []string{"tools/query"},
		Remember:       true,
	})
	if err != nil {
		t.Fatalf("grant consent: %v", err)
	}
	if result.Code == "" {
		t.Error("expected authorization code")
	}
	if result.RedirectURI == "" {
		t.Error("expected redirect URI")
	}
}

// --- Session Expiry Guard ---

func TestSession_ExpiredSession_RejectsCodeHash(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	ctx := context.Background()
	now := time.Now().UTC()

	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "Expired Session Test",
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

	// Create an already-expired session.
	code := crypto.GenerateAuthCode()
	verifier := crypto.GenerateVerifier()
	sess := &session.AuthSession{
		ID:                  crypto.GenerateRandomString(16),
		ClientID:            c.ID,
		UserID:              "expired-user",
		RedirectURI:         "https://app.example.com/callback",
		Scope:               "tools/query",
		Resource:            "https://mcp.example.com",
		State:               "state-expired",
		CodeHash:            crypto.HashSHA256(code),
		CodeChallenge:       crypto.ComputeS256Challenge(verifier),
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(-1 * time.Minute), // Already expired.
		CreatedAt:           now.Add(-15 * time.Minute),
	}
	if err := stores.Session.Create(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Attempt to update code hash on expired session.
	newCode := crypto.GenerateAuthCode()
	newHash := crypto.HashSHA256(newCode)
	err := stores.Session.UpdateCodeHashAndScope(ctx, sess.ID, newHash, "tools/query")
	if err == nil {
		t.Fatal("expected error updating code hash on expired session")
	}
}
