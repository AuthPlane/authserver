//go:build integration

package services_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/scope"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

type adminTestSetup struct {
	adminSvc *services.AdminService
	stores   *testdata.TestHelper
}

func newAdminTestSetup(t *testing.T) *adminTestSetup {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	adminSvc := services.NewAdminService(
		stores.Client, stores.User, stores.Token, stores.Audit,
		obs, nil,
		services.WithMachineTokenStore(stores.MachineToken),
		services.WithRevocationStore(stores.Revocation),
	)
	return &adminTestSetup{
		adminSvc: adminSvc,
		stores:   &testdata.TestHelper{Stores: stores},
	}
}

func (s *adminTestSetup) createTestClient(t *testing.T) *client.Client {
	t.Helper()
	return s.createTestClientWithID(t, crypto.GenerateClientID())
}

// createTokenFamily seeds the parent client + user rows for the family's
// FK columns and persists the family. Tests that previously
// inserted token_families with bare client_id / user_id strings must go
// through this helper so the FK constraint is satisfied.
func (s *adminTestSetup) createTokenFamily(t *testing.T, ctx context.Context, family *token.Family) {
	t.Helper()
	testdata.EnsureClient(t, s.stores.Stores.Client, family.ClientID)
	testdata.EnsureUser(t, s.stores.Stores.User, family.UserID)
	if err := s.stores.Stores.Token.CreateFamily(ctx, family); err != nil {
		t.Fatalf("create token family: %v", err)
	}
}

func (s *adminTestSetup) createTestClientWithID(t *testing.T, id string) *client.Client {
	t.Helper()
	now := time.Now().UTC()
	c := &client.Client{
		ID:                      id,
		Name:                    "Admin Test",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceDCR,
		IssuedAt:                now,
		UpdatedAt:               now,
	}
	if err := s.stores.Stores.Client.Create(context.Background(), c); err != nil {
		t.Fatalf("create client: %v", err)
	}
	return c
}

func TestAdmin_ListClients(t *testing.T) {
	setup := newAdminTestSetup(t)
	setup.createTestClient(t)
	setup.createTestClient(t)

	clients, err := setup.adminSvc.ListClients(context.Background(), input.ClientFilter{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(clients) < 2 {
		t.Errorf("expected at least 2 clients, got %d", len(clients))
	}
}

func TestAdmin_GetClient(t *testing.T) {
	setup := newAdminTestSetup(t)
	c := setup.createTestClient(t)

	got, err := setup.adminSvc.GetClient(context.Background(), c.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != c.ID {
		t.Errorf("id: got %q, want %q", got.ID, c.ID)
	}
}

func TestAdmin_SuspendClient(t *testing.T) {
	setup := newAdminTestSetup(t)
	c := setup.createTestClient(t)

	if err := setup.adminSvc.SuspendClient(context.Background(), c.ID); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	got, _ := setup.adminSvc.GetClient(context.Background(), c.ID)
	if got.Status != client.StatusSuspended {
		t.Errorf("status: got %q, want suspended", got.Status)
	}
}

func TestAdmin_RevokeClient(t *testing.T) {
	setup := newAdminTestSetup(t)
	c := setup.createTestClient(t)

	if err := setup.adminSvc.RevokeClient(context.Background(), c.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	got, _ := setup.adminSvc.GetClient(context.Background(), c.ID)
	if got.Status != client.StatusRevoked {
		t.Errorf("status: got %q, want revoked", got.Status)
	}
}

func TestAdmin_ReactivateClient(t *testing.T) {
	setup := newAdminTestSetup(t)
	c := setup.createTestClient(t)

	// Suspend first, then reactivate.
	setup.adminSvc.SuspendClient(context.Background(), c.ID)
	if err := setup.adminSvc.ReactivateClient(context.Background(), c.ID); err != nil {
		t.Fatalf("reactivate: %v", err)
	}

	got, _ := setup.adminSvc.GetClient(context.Background(), c.ID)
	if got.Status != client.StatusActive {
		t.Errorf("status: got %q, want active", got.Status)
	}
}

func TestAdmin_CreateAndListUsers(t *testing.T) {
	setup := newAdminTestSetup(t)

	u, err := setup.adminSvc.CreateUser(context.Background(), input.CreateUserRequest{
		Email:    "admin@example.com",
		Password: "secret123",
		Role:     user.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.ID == "" {
		t.Error("id is empty")
	}
	if u.Role != user.RoleAdmin {
		t.Errorf("role: got %q", u.Role)
	}

	users, err := setup.adminSvc.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
}

func TestAdmin_DisableAndEnableUser(t *testing.T) {
	setup := newAdminTestSetup(t)

	u, _ := setup.adminSvc.CreateUser(context.Background(), input.CreateUserRequest{
		Email:    "toggle@example.com",
		Password: "pass",
		Role:     user.RoleUser,
	})

	if err := setup.adminSvc.DisableUser(context.Background(), u.ID); err != nil {
		t.Fatalf("disable: %v", err)
	}

	got, _ := setup.adminSvc.GetUser(context.Background(), u.ID)
	if got.Status != user.StatusDisabled {
		t.Errorf("status after disable: got %q", got.Status)
	}

	if err := setup.adminSvc.EnableUser(context.Background(), u.ID); err != nil {
		t.Fatalf("enable: %v", err)
	}

	got, _ = setup.adminSvc.GetUser(context.Background(), u.ID)
	if got.Status != user.StatusActive {
		t.Errorf("status after enable: got %q", got.Status)
	}
}

func TestAdmin_CreateClient_Confidential(t *testing.T) {
	setup := newAdminTestSetup(t)

	resp, err := setup.adminSvc.CreateClient(context.Background(), input.CreateClientRequest{
		Name:                    "My MCP Server",
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
		Scope:                   "mcp:read mcp:write",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if resp.Client.ID == "" {
		t.Error("client ID is empty")
	}
	if resp.ClientSecret == "" {
		t.Error("client secret should be set for confidential client")
	}
	if resp.Client.RegistrationSource != client.SourceAdmin {
		t.Errorf("source: got %q, want admin", resp.Client.RegistrationSource)
	}
	if resp.Client.Scope != "mcp:read mcp:write" {
		t.Errorf("scope: got %q", resp.Client.Scope)
	}

	// Verify persisted.
	got, err := setup.adminSvc.GetClient(context.Background(), resp.Client.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.SecretHash == "" {
		t.Error("secret hash should be stored")
	}
}

func TestAdmin_CreateClient_Public(t *testing.T) {
	setup := newAdminTestSetup(t)

	resp, err := setup.adminSvc.CreateClient(context.Background(), input.CreateClientRequest{
		Name:                    "Public SPA",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "none",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if resp.ClientSecret != "" {
		t.Error("public client should not have a secret")
	}
}

func TestAdmin_CreateClient_ValidationError(t *testing.T) {
	setup := newAdminTestSetup(t)

	// Missing name.
	_, err := setup.adminSvc.CreateClient(context.Background(), input.CreateClientRequest{
		RedirectURIs: []string{"https://app.example.com/callback"},
	})
	if err == nil {
		t.Fatal("should fail with validation error")
	}
}

func TestAdmin_CreateClient_AgentFields(t *testing.T) {
	setup := newAdminTestSetup(t)

	resp, err := setup.adminSvc.CreateClient(context.Background(), input.CreateClientRequest{
		Name:                    "Agent Bot",
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
		IsAgent:                 true,
		AgentDescription:        "A helpful agent",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !resp.Client.IsAgent {
		t.Error("is_agent should be true")
	}
	if resp.Client.AgentDescription != "A helpful agent" {
		t.Errorf("agent_description: got %q", resp.Client.AgentDescription)
	}
}

// AdminService must reject CreateClient when the requested
// grant_type is not in the configured enabledGrants set, and the error
// must name the env var the operator must flip.
func TestAdmin_CreateClient_GrantNotEnabled_Rejected(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	adminSvc := services.NewAdminService(
		stores.Client, stores.User, stores.Token, stores.Audit,
		obs, nil,
		services.WithMachineTokenStore(stores.MachineToken),
		services.WithRevocationStore(stores.Revocation),
		services.WithEnabledGrants(staticGrantsForTest{grants: []string{"authorization_code", "refresh_token"}}),
	)

	_, err := adminSvc.CreateClient(context.Background(), input.CreateClientRequest{
		Name:                    "CC Client",
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	if err == nil {
		t.Fatal("admin must reject client_credentials when not enabled")
	}
	if !strings.Contains(err.Error(), "client_credentials") {
		t.Errorf("error should name the offending grant: %v", err)
	}
	if !strings.Contains(err.Error(), "AUTHPLANE_CLIENT_CREDENTIALS_ENABLED") {
		t.Errorf("error should name the env var: %v", err)
	}
}

// UpdateClient must reject swapping in a disabled grant, otherwise
// an operator could bypass the create-time check by editing later.
func TestAdmin_UpdateClient_GrantNotEnabled_Rejected(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	adminSvc := services.NewAdminService(
		stores.Client, stores.User, stores.Token, stores.Audit,
		obs, nil,
		services.WithMachineTokenStore(stores.MachineToken),
		services.WithRevocationStore(stores.Revocation),
		services.WithEnabledGrants(staticGrantsForTest{grants: []string{"authorization_code", "refresh_token"}}),
	)

	resp, err := adminSvc.CreateClient(context.Background(), input.CreateClientRequest{
		Name:                    "OK Client",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "none",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	bad := []string{"client_credentials"}
	_, err = adminSvc.UpdateClient(context.Background(), resp.Client.ID, input.UpdateClientRequest{
		GrantTypes: &bad,
	})
	if err == nil {
		t.Fatal("update must reject swap to disabled grant")
	}
	if !strings.Contains(err.Error(), "AUTHPLANE_CLIENT_CREDENTIALS_ENABLED") {
		t.Errorf("update error should name the env var: %v", err)
	}
}

func TestAdmin_UpdateClient_PartialUpdate(t *testing.T) {
	setup := newAdminTestSetup(t)

	resp, err := setup.adminSvc.CreateClient(context.Background(), input.CreateClientRequest{
		Name:                    "Original Name",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "none",
		Scope:                   "read write",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Update only name.
	newName := "Updated Name"
	updated, err := setup.adminSvc.UpdateClient(context.Background(), resp.Client.ID, input.UpdateClientRequest{
		Name: &newName,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "Updated Name" {
		t.Errorf("name: got %q", updated.Name)
	}
	// Other fields should be unchanged.
	if updated.Scope != "read write" {
		t.Errorf("scope should be unchanged: got %q", updated.Scope)
	}
	if len(updated.RedirectURIs) != 1 || updated.RedirectURIs[0] != "https://app.example.com/callback" {
		t.Errorf("redirect_uris should be unchanged: got %v", updated.RedirectURIs)
	}
}

func TestAdmin_UpdateClient_FullUpdate(t *testing.T) {
	setup := newAdminTestSetup(t)

	resp, err := setup.adminSvc.CreateClient(context.Background(), input.CreateClientRequest{
		Name:                    "Full Update",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "none",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	newName := "Fully Updated"
	newURIs := []string{"https://new.example.com/cb"}
	newGrants := []string{"authorization_code", "refresh_token"}
	newScope := "new:scope"

	updated, err := setup.adminSvc.UpdateClient(context.Background(), resp.Client.ID, input.UpdateClientRequest{
		Name:         &newName,
		RedirectURIs: &newURIs,
		GrantTypes:   &newGrants,
		Scope:        &newScope,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "Fully Updated" {
		t.Errorf("name: got %q", updated.Name)
	}
	if len(updated.RedirectURIs) != 1 || updated.RedirectURIs[0] != "https://new.example.com/cb" {
		t.Errorf("redirect_uris: got %v", updated.RedirectURIs)
	}
	if updated.Scope != "new:scope" {
		t.Errorf("scope: got %q", updated.Scope)
	}
}

func TestAdmin_UpdateClient_ValidationError(t *testing.T) {
	setup := newAdminTestSetup(t)

	resp, err := setup.adminSvc.CreateClient(context.Background(), input.CreateClientRequest{
		Name:                    "Validation Test",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "none",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Set name to empty — should fail validation.
	emptyName := ""
	_, err = setup.adminSvc.UpdateClient(context.Background(), resp.Client.ID, input.UpdateClientRequest{
		Name: &emptyName,
	})
	if err == nil {
		t.Fatal("should fail with validation error for empty name")
	}
}

func TestAdmin_UpdateClient_NotFound(t *testing.T) {
	setup := newAdminTestSetup(t)

	newName := "Ghost"
	_, err := setup.adminSvc.UpdateClient(context.Background(), "nonexistent", input.UpdateClientRequest{
		Name: &newName,
	})
	if err == nil {
		t.Fatal("should fail for non-existent client")
	}
}

func TestAdmin_RotateClientSecret_Confidential(t *testing.T) {
	setup := newAdminTestSetup(t)

	// Create a confidential client first.
	resp, err := setup.adminSvc.CreateClient(context.Background(), input.CreateClientRequest{
		Name:                    "Rotate Me",
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	oldSecret := resp.ClientSecret

	// Rotate.
	rotated, err := setup.adminSvc.RotateClientSecret(context.Background(), resp.Client.ID)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rotated.ClientSecret == "" {
		t.Error("new secret should not be empty")
	}
	if rotated.ClientSecret == oldSecret {
		t.Error("new secret should differ from old secret")
	}

	// Verify the hash changed in the store.
	got, _ := setup.adminSvc.GetClient(context.Background(), resp.Client.ID)
	if got.SecretHash == resp.Client.SecretHash {
		t.Error("stored hash should have changed")
	}
}

func TestAdmin_RotateClientSecret_PublicClient_Rejected(t *testing.T) {
	setup := newAdminTestSetup(t)

	// Create a public client.
	resp, err := setup.adminSvc.CreateClient(context.Background(), input.CreateClientRequest{
		Name:                    "Public App",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "none",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Rotate should fail.
	_, err = setup.adminSvc.RotateClientSecret(context.Background(), resp.Client.ID)
	if err == nil {
		t.Fatal("should reject rotation for public client")
	}
}

func TestAdmin_RotateClientSecret_NotFound(t *testing.T) {
	setup := newAdminTestSetup(t)

	_, err := setup.adminSvc.RotateClientSecret(context.Background(), "nonexistent-id")
	if err == nil {
		t.Fatal("should fail for non-existent client")
	}
}

func TestAdmin_GetStats(t *testing.T) {
	setup := newAdminTestSetup(t)
	ctx := context.Background()

	// Create some data.
	setup.createTestClient(t)

	setup.adminSvc.CreateUser(ctx, input.CreateUserRequest{
		Email: "stats@example.com", Password: "p", Role: user.RoleUser,
	})

	// Create a token family.
	now := time.Now().UTC()
	family := &token.Family{
		ID:        crypto.GenerateRandomString(16),
		ClientID:  "stat-client",
		UserID:    "stat-user",
		Scope:     "tools/query",
		Status:    token.FamilyActive,
		CreatedAt: now,
	}
	setup.createTokenFamily(t, ctx, family)

	stats, err := setup.adminSvc.GetStats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.TotalClients < 1 {
		t.Errorf("total_clients: got %d", stats.TotalClients)
	}
	if stats.TotalUsers < 1 {
		t.Errorf("total_users: got %d", stats.TotalUsers)
	}
	if stats.TokensIssuedToday < 1 {
		t.Errorf("tokens_issued_today: got %d", stats.TokensIssuedToday)
	}
}

// --- Token management tests ---

func TestAdmin_ListTokens(t *testing.T) {
	setup := newAdminTestSetup(t)
	ctx := context.Background()

	// Create token families.
	now := time.Now().UTC()
	for range 3 {
		family := &token.Family{
			ID:        crypto.GenerateRandomString(16),
			ClientID:  "list-tokens-client",
			UserID:    "list-tokens-user",
			Scope:     "tools/query",
			Status:    token.FamilyActive,
			CreatedAt: now,
		}
		setup.createTokenFamily(t, ctx, family)
	}

	resp, err := setup.adminSvc.ListTokens(ctx, input.TokenFilter{
		ClientID: "list-tokens-client",
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if resp.Total < 3 {
		t.Errorf("total: got %d, want >= 3", resp.Total)
	}
	for _, tv := range resp.Tokens {
		if tv.Type != "authorization_code" {
			t.Errorf("type: got %q, want authorization_code", tv.Type)
		}
	}
}

func TestAdmin_ListTokens_WithMachineTokens(t *testing.T) {
	setup := newAdminTestSetup(t)
	ctx := context.Background()

	// Seed the parent client row for the machine_tokens.client_id FK.
	setup.createTestClientWithID(t, "machine-client")

	// Create a machine token.
	mt := token.MachineToken{
		JTI:       crypto.GenerateRandomString(16),
		ClientID:  "machine-client",
		Scopes:    scope.Parse("tools/query"),
		Resource:  "https://api.example.com",
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		Revoked:   false,
	}
	if err := setup.stores.Stores.MachineToken.Save(ctx, mt); err != nil {
		t.Fatalf("save machine token: %v", err)
	}

	resp, err := setup.adminSvc.ListTokens(ctx, input.TokenFilter{
		ClientID: "machine-client",
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if resp.Total < 1 {
		t.Errorf("total: got %d, want >= 1", resp.Total)
	}

	found := false
	for _, tv := range resp.Tokens {
		if tv.JTI == mt.JTI {
			found = true
			if tv.Type != "client_credentials" {
				t.Errorf("type: got %q, want client_credentials", tv.Type)
			}
		}
	}
	if !found {
		t.Error("machine token not found in list response")
	}
}

func TestAdmin_ListUserTokens(t *testing.T) {
	setup := newAdminTestSetup(t)
	ctx := context.Background()

	// Create user first.
	u, err := setup.adminSvc.CreateUser(ctx, input.CreateUserRequest{
		Email: "tokens@example.com", Password: "pass", Role: user.RoleUser,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Create a family for this user.
	family := &token.Family{
		ID:        crypto.GenerateRandomString(16),
		ClientID:  "user-token-client",
		UserID:    u.ID,
		Scope:     "tools/query",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	}
	setup.createTokenFamily(t, ctx, family)

	resp, err := setup.adminSvc.ListUserTokens(ctx, u.ID, 10, 0)
	if err != nil {
		t.Fatalf("list user tokens: %v", err)
	}
	if resp.Total < 1 {
		t.Errorf("total: got %d, want >= 1", resp.Total)
	}
}

func TestAdmin_ListUserTokens_UserNotFound(t *testing.T) {
	setup := newAdminTestSetup(t)
	_, err := setup.adminSvc.ListUserTokens(context.Background(), "nonexistent", 10, 0)
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
}

func TestAdmin_RevokeToken_Family(t *testing.T) {
	setup := newAdminTestSetup(t)
	ctx := context.Background()

	family := &token.Family{
		ID:        crypto.GenerateRandomString(16),
		ClientID:  "revoke-client",
		UserID:    "revoke-user",
		Scope:     "tools/query",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	}
	setup.createTokenFamily(t, ctx, family)

	if err := setup.adminSvc.RevokeToken(ctx, family.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Verify family is revoked.
	got, err := setup.stores.Stores.Token.GetFamily(ctx, family.ID)
	if err != nil {
		t.Fatalf("get family: %v", err)
	}
	if got.Status != token.FamilyRevoked {
		t.Errorf("status: got %q, want revoked", got.Status)
	}
}

func TestAdmin_RevokeToken_MachineToken(t *testing.T) {
	setup := newAdminTestSetup(t)
	ctx := context.Background()

	// Seed the parent client row for the machine_tokens.client_id FK.
	setup.createTestClientWithID(t, "revoke-machine-client")

	mt := token.MachineToken{
		JTI:       crypto.GenerateRandomString(16),
		ClientID:  "revoke-machine-client",
		Scopes:    scope.Parse("tools/query"),
		Resource:  "https://api.example.com",
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		Revoked:   false,
	}
	if err := setup.stores.Stores.MachineToken.Save(ctx, mt); err != nil {
		t.Fatalf("save machine token: %v", err)
	}

	if err := setup.adminSvc.RevokeToken(ctx, mt.JTI); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	got, err := setup.stores.Stores.MachineToken.GetByJTI(ctx, mt.JTI)
	if err != nil {
		t.Fatalf("get machine token: %v", err)
	}
	if !got.Revoked {
		t.Error("expected machine token to be revoked")
	}
}

func TestAdmin_RevokeToken_NotFound(t *testing.T) {
	setup := newAdminTestSetup(t)
	err := setup.adminSvc.RevokeToken(context.Background(), "nonexistent-jti")
	if err == nil {
		t.Fatal("expected error for nonexistent token")
	}
}

// --- Force Logout ---

// --- Delete Client ---

func TestAdmin_DeleteClient_NoTokens(t *testing.T) {
	setup := newAdminTestSetup(t)
	ctx := context.Background()

	c := setup.createTestClient(t)

	if err := setup.adminSvc.DeleteClient(ctx, c.ID, false); err != nil {
		t.Fatalf("delete client: %v", err)
	}

	// Verify client is gone.
	_, err := setup.stores.Stores.Client.GetByID(ctx, c.ID)
	if err == nil {
		t.Fatal("expected error for deleted client")
	}
}

func TestAdmin_DeleteClient_WithTokens_NoForce(t *testing.T) {
	setup := newAdminTestSetup(t)
	ctx := context.Background()

	c := setup.createTestClient(t)

	// Create an active token family for this client.
	family := &token.Family{
		ID:        crypto.GenerateRandomString(16),
		ClientID:  c.ID,
		UserID:    "test-user",
		Scope:     "tools/query",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	}
	setup.createTokenFamily(t, ctx, family)

	err := setup.adminSvc.DeleteClient(ctx, c.ID, false)
	if err == nil {
		t.Fatal("expected conflict error")
	}

	// Client should still exist.
	got, err := setup.stores.Stores.Client.GetByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("client should still exist: %v", err)
	}
	if got.ID != c.ID {
		t.Errorf("client ID mismatch: got %s, want %s", got.ID, c.ID)
	}
}

func TestAdmin_DeleteClient_WithTokens_Force(t *testing.T) {
	setup := newAdminTestSetup(t)
	ctx := context.Background()

	c := setup.createTestClient(t)

	// Create an active token family for this client.
	family := &token.Family{
		ID:        crypto.GenerateRandomString(16),
		ClientID:  c.ID,
		UserID:    "test-user",
		Scope:     "tools/query",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	}
	setup.createTokenFamily(t, ctx, family)

	if err := setup.adminSvc.DeleteClient(ctx, c.ID, true); err != nil {
		t.Fatalf("force delete: %v", err)
	}

	// Client should be gone.
	_, err := setup.stores.Stores.Client.GetByID(ctx, c.ID)
	if err == nil {
		t.Fatal("expected error for deleted client")
	}
}

func TestAdmin_DeleteClient_NotFound(t *testing.T) {
	setup := newAdminTestSetup(t)
	err := setup.adminSvc.DeleteClient(context.Background(), "nonexistent-id", false)
	if err == nil {
		t.Fatal("expected error for nonexistent client")
	}
}

func TestAdmin_ForceLogoutUser(t *testing.T) {
	setup := newAdminTestSetup(t)
	ctx := context.Background()

	// Create user.
	u, err := setup.adminSvc.CreateUser(ctx, input.CreateUserRequest{
		Email: "logout@example.com", Password: "pass", Role: user.RoleUser,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Create two token families for this user.
	for i := range 2 {
		family := &token.Family{
			ID:        crypto.GenerateRandomString(16),
			ClientID:  "logout-client",
			UserID:    u.ID,
			Scope:     "tools/query",
			Status:    token.FamilyActive,
			CreatedAt: time.Now().UTC().Add(-time.Duration(i) * time.Minute),
		}
		setup.createTokenFamily(t, ctx, family)
	}

	count, err := setup.adminSvc.ForceLogoutUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("force logout: %v", err)
	}
	if count < 2 {
		t.Errorf("tokens_revoked: got %d, want >= 2", count)
	}

	// Verify user's tokens are now revoked.
	resp, err := setup.adminSvc.ListUserTokens(ctx, u.ID, 50, 0)
	if err != nil {
		t.Fatalf("list user tokens: %v", err)
	}
	for _, tok := range resp.Tokens {
		if tok.Status == "active" {
			t.Errorf("expected all tokens revoked, got active: %s", tok.JTI)
		}
	}
}

func TestAdmin_ForceLogoutUser_UserNotFound(t *testing.T) {
	setup := newAdminTestSetup(t)
	_, err := setup.adminSvc.ForceLogoutUser(context.Background(), "nonexistent-user")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
}

func TestAdmin_ForceLogoutUser_NoTokens(t *testing.T) {
	setup := newAdminTestSetup(t)
	ctx := context.Background()

	// Create user with no tokens.
	u, err := setup.adminSvc.CreateUser(ctx, input.CreateUserRequest{
		Email: "notokens@example.com", Password: "pass", Role: user.RoleUser,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	count, err := setup.adminSvc.ForceLogoutUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("force logout: %v", err)
	}
	if count != 0 {
		t.Errorf("tokens_revoked: got %d, want 0", count)
	}
}

// --- Update + Delete User ---

func TestAdmin_UpdateUser(t *testing.T) {
	setup := newAdminTestSetup(t)
	ctx := context.Background()

	u, err := setup.adminSvc.CreateUser(ctx, input.CreateUserRequest{
		Email: "update@example.com", Password: "pass", Name: "Original", Role: user.RoleUser,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	newEmail := "updated@example.com"
	newName := "Updated Name"
	updated, err := setup.adminSvc.UpdateUser(ctx, u.ID, input.UpdateUserRequest{
		Email: &newEmail,
		Name:  &newName,
	})
	if err != nil {
		t.Fatalf("update user: %v", err)
	}
	if updated.Email != newEmail {
		t.Errorf("email: got %s, want %s", updated.Email, newEmail)
	}
	if updated.Name != newName {
		t.Errorf("name: got %s, want %s", updated.Name, newName)
	}
}

func TestAdmin_UpdateUser_PartialUpdate(t *testing.T) {
	setup := newAdminTestSetup(t)
	ctx := context.Background()

	u, err := setup.adminSvc.CreateUser(ctx, input.CreateUserRequest{
		Email: "partial@example.com", Password: "pass", Name: "Original", Role: user.RoleUser,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	newName := "New Name Only"
	updated, err := setup.adminSvc.UpdateUser(ctx, u.ID, input.UpdateUserRequest{
		Name: &newName,
	})
	if err != nil {
		t.Fatalf("update user: %v", err)
	}
	if updated.Email != "partial@example.com" {
		t.Errorf("email should be unchanged: got %s", updated.Email)
	}
	if updated.Name != newName {
		t.Errorf("name: got %s, want %s", updated.Name, newName)
	}
}

func TestAdmin_DeleteUser_NoTokens(t *testing.T) {
	setup := newAdminTestSetup(t)
	ctx := context.Background()

	u, err := setup.adminSvc.CreateUser(ctx, input.CreateUserRequest{
		Email: "delete@example.com", Password: "pass", Role: user.RoleUser,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	if err := setup.adminSvc.DeleteUser(ctx, u.ID, false); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	_, err = setup.stores.Stores.User.GetByID(ctx, u.ID)
	if err == nil {
		t.Fatal("expected error for deleted user")
	}
}

func TestAdmin_DeleteUser_WithTokens_NoForce(t *testing.T) {
	setup := newAdminTestSetup(t)
	ctx := context.Background()

	u, err := setup.adminSvc.CreateUser(ctx, input.CreateUserRequest{
		Email: "nodelete@example.com", Password: "pass", Role: user.RoleUser,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	family := &token.Family{
		ID:        crypto.GenerateRandomString(16),
		ClientID:  "del-user-client",
		UserID:    u.ID,
		Scope:     "tools/query",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	}
	setup.createTokenFamily(t, ctx, family)

	err = setup.adminSvc.DeleteUser(ctx, u.ID, false)
	if err == nil {
		t.Fatal("expected conflict error")
	}
}

func TestAdmin_DeleteUser_WithTokens_Force(t *testing.T) {
	setup := newAdminTestSetup(t)
	ctx := context.Background()

	u, err := setup.adminSvc.CreateUser(ctx, input.CreateUserRequest{
		Email: "forcedelete@example.com", Password: "pass", Role: user.RoleUser,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	family := &token.Family{
		ID:        crypto.GenerateRandomString(16),
		ClientID:  "del-user-client",
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
		t.Fatal("expected error for deleted user")
	}
}

// TestAdmin_CreateClient_GrantsProviderError_Rejected verifies fail-closed: when
// the enabled-grants provider errors, CreateClient rejects.
func TestAdmin_CreateClient_GrantsProviderError_Rejected(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	adminSvc := services.NewAdminService(
		stores.Client, stores.User, stores.Token, stores.Audit,
		obs, nil,
		services.WithMachineTokenStore(stores.MachineToken),
		services.WithRevocationStore(stores.Revocation),
		services.WithEnabledGrants(failingGrantsForTest{}),
	)

	_, err := adminSvc.CreateClient(context.Background(), input.CreateClientRequest{
		Name:         "fail closed",
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
	})
	if !errors.Is(err, errGrantsUnavailable) {
		t.Fatalf("expected wrapped errGrantsUnavailable, got %v", err)
	}
}
