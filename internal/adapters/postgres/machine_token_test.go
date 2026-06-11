//go:build integration_postgres

package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/scope"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/testdata"
)

func TestMachineTokenStore(t *testing.T) {
	testdata.RunMachineTokenStoreTests(t, func(t *testing.T) (output.MachineTokenStore, output.ClientStore) {
		stores := testdata.SetupTestPGStores(t, pgContainerDSN)
		return stores.MachineToken, stores.Client
	})
}

// TestMachineTokenStore_CascadeDelete verifies the ON DELETE CASCADE FK
// constraint on machine_tokens.client_id: deleting a client directly via
// raw SQL must remove its machine tokens. This test requires raw DB
// access and cannot be expressed through the store interface alone.
func TestMachineTokenStore_CascadeDelete(t *testing.T) {
	db := testdata.SetupTestPGDB(t, pgContainerDSN)
	stores := db.NewStores()
	ctx := context.Background()

	c := &client.Client{
		ID:                      "client-cascade",
		Name:                    "Cascade Client",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"client_credentials"},
		ResponseTypes:           []string{},
		TokenEndpointAuthMethod: "client_secret_basic",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceDCR,
		IssuedAt:                time.Now().UTC(),
		UpdatedAt:               time.Now().UTC(),
	}
	if err := stores.Client.Create(ctx, c); err != nil {
		t.Fatalf("create client: %v", err)
	}

	now := time.Now().UTC()
	mt := token.MachineToken{
		JTI:       "mt-cascade",
		ClientID:  "client-cascade",
		Scopes:    scope.New("read"),
		Resource:  "https://api.example.com",
		IssuedAt:  now,
		ExpiresAt: now.Add(1 * time.Hour),
	}
	if err := stores.MachineToken.Save(ctx, mt); err != nil {
		t.Fatalf("save machine token: %v", err)
	}

	// Delete client directly via pool — the machine token row should cascade away.
	if _, err := db.Pool.Exec(ctx, `DELETE FROM clients WHERE id = $1`, "client-cascade"); err != nil {
		t.Fatalf("delete client: %v", err)
	}

	got, err := stores.MachineToken.GetByJTI(ctx, "mt-cascade")
	if err != nil {
		t.Fatalf("get after cascade: %v", err)
	}
	if got != nil {
		t.Errorf("expected machine token to be cascade-deleted, got %+v", got)
	}
}

// TestMachineTokenStore_FKViolation verifies the DB rejects a machine
// token whose client_id does not match any row in clients.
func TestMachineTokenStore_FKViolation(t *testing.T) {
	stores := testdata.SetupTestPGStores(t, pgContainerDSN)
	ctx := context.Background()

	now := time.Now().UTC()
	mt := token.MachineToken{
		JTI:       "mt-no-client",
		ClientID:  "nonexistent-client",
		Scopes:    scope.New("read"),
		Resource:  "https://api.example.com",
		IssuedAt:  now,
		ExpiresAt: now.Add(1 * time.Hour),
	}
	if err := stores.MachineToken.Save(ctx, mt); err == nil {
		t.Fatal("expected FK violation error when saving machine token with missing client, got nil")
	}
}
