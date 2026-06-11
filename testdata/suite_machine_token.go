package testdata

import (
	"context"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain/scope"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/ports/output"
)

func newTestMachineToken(jti, clientID string) token.MachineToken {
	now := time.Now().UTC()
	return token.MachineToken{
		JTI:       jti,
		ClientID:  clientID,
		Scopes:    scope.New("read", "write"),
		Resource:  "https://api.example.com",
		IssuedAt:  now,
		ExpiresAt: now.Add(15 * time.Minute),
		Revoked:   false,
	}
}

// RunMachineTokenStoreTests runs the full MachineTokenStore contract tests.
// The factory returns a fresh MachineTokenStore plus the ClientStore needed
// to seed the parent client row that the client_id FK points at.
func RunMachineTokenStoreTests(t *testing.T, newStores func(*testing.T) (output.MachineTokenStore, output.ClientStore)) {
	t.Helper()

	// Helper to seed a client (required for the machine_tokens.client_id FK).
	seedClient := func(t *testing.T, cs output.ClientStore, id string) {
		t.Helper()
		if err := cs.Create(context.Background(), newTestClient(id)); err != nil {
			t.Fatalf("seed client %q: %v", id, err)
		}
	}

	t.Run("SaveAndGetByJTI", func(t *testing.T) {
		store, clients := newStores(t)
		ctx := context.Background()
		seedClient(t, clients, "client-1")

		mt := newTestMachineToken("jti-1", "client-1")
		if err := store.Save(ctx, mt); err != nil {
			t.Fatalf("save: %v", err)
		}

		got, err := store.GetByJTI(ctx, "jti-1")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got == nil {
			t.Fatal("expected machine token, got nil")
		}
		if got.JTI != "jti-1" {
			t.Errorf("jti = %q, want %q", got.JTI, "jti-1")
		}
		if got.ClientID != "client-1" {
			t.Errorf("client_id = %q, want %q", got.ClientID, "client-1")
		}
		if got.Scopes.String() != "read write" {
			t.Errorf("scopes = %q, want %q", got.Scopes.String(), "read write")
		}
		if got.Resource != "https://api.example.com" {
			t.Errorf("resource = %q, want %q", got.Resource, "https://api.example.com")
		}
		if got.Revoked {
			t.Error("expected revoked = false")
		}
	})

	t.Run("GetByJTI_NotFound", func(t *testing.T) {
		store, _ := newStores(t)
		ctx := context.Background()

		got, err := store.GetByJTI(ctx, "nonexistent")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})

	t.Run("Revoke", func(t *testing.T) {
		store, clients := newStores(t)
		ctx := context.Background()
		seedClient(t, clients, "client-1")

		mt := newTestMachineToken("jti-revoke", "client-1")
		if err := store.Save(ctx, mt); err != nil {
			t.Fatalf("save: %v", err)
		}

		if err := store.Revoke(ctx, "jti-revoke"); err != nil {
			t.Fatalf("revoke: %v", err)
		}

		got, err := store.GetByJTI(ctx, "jti-revoke")
		if err != nil {
			t.Fatalf("get after revoke: %v", err)
		}
		if got == nil {
			t.Fatal("expected machine token, got nil")
		}
		if !got.Revoked {
			t.Error("expected revoked = true after Revoke()")
		}
	})

	t.Run("Revoke_Nonexistent_NoError", func(t *testing.T) {
		store, _ := newStores(t)
		ctx := context.Background()

		// Revoking a nonexistent JTI should not error.
		if err := store.Revoke(ctx, "nonexistent"); err != nil {
			t.Errorf("revoke nonexistent: %v", err)
		}
	})

	t.Run("PurgeExpired", func(t *testing.T) {
		store, clients := newStores(t)
		ctx := context.Background()
		seedClient(t, clients, "client-1")

		// Create an expired token.
		expired := newTestMachineToken("jti-expired", "client-1")
		expired.IssuedAt = time.Now().UTC().Add(-2 * time.Hour)
		expired.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour)
		if err := store.Save(ctx, expired); err != nil {
			t.Fatalf("save expired: %v", err)
		}

		// Create a non-expired token.
		active := newTestMachineToken("jti-active", "client-1")
		if err := store.Save(ctx, active); err != nil {
			t.Fatalf("save active: %v", err)
		}

		// Purge expired.
		if err := store.PurgeExpired(ctx); err != nil {
			t.Fatalf("purge: %v", err)
		}

		// Expired should be gone.
		got, err := store.GetByJTI(ctx, "jti-expired")
		if err != nil {
			t.Fatalf("get expired: %v", err)
		}
		if got != nil {
			t.Error("expected expired token to be purged")
		}

		// Active should remain.
		got, err = store.GetByJTI(ctx, "jti-active")
		if err != nil {
			t.Fatalf("get active: %v", err)
		}
		if got == nil {
			t.Error("expected active token to remain after purge")
		}
	})

	t.Run("DuplicateJTI_Errors", func(t *testing.T) {
		store, clients := newStores(t)
		ctx := context.Background()
		seedClient(t, clients, "client-1")

		mt := newTestMachineToken("jti-dup", "client-1")
		if err := store.Save(ctx, mt); err != nil {
			t.Fatalf("first save: %v", err)
		}

		// Second save with same JTI should error (unique constraint).
		err := store.Save(ctx, mt)
		if err == nil {
			t.Error("expected error on duplicate JTI, got nil")
		}
	})

	t.Run("CountIssuedSince", func(t *testing.T) {
		store, clients := newStores(t)
		ctx := context.Background()
		seedClient(t, clients, "client-1")

		// Create a token now.
		mt := newTestMachineToken("jti-count-1", "client-1")
		if err := store.Save(ctx, mt); err != nil {
			t.Fatalf("save: %v", err)
		}

		// Count since 1 hour ago — should include the token.
		since := time.Now().UTC().Add(-1 * time.Hour).Unix()
		count, err := store.CountIssuedSince(ctx, since)
		if err != nil {
			t.Fatalf("count issued since: %v", err)
		}
		if count < 1 {
			t.Errorf("count = %d, want >= 1", count)
		}

		// Count since 1 hour in the future — should be 0.
		future := time.Now().UTC().Add(1 * time.Hour).Unix()
		count, err = store.CountIssuedSince(ctx, future)
		if err != nil {
			t.Fatalf("count issued since future: %v", err)
		}
		if count != 0 {
			t.Errorf("count = %d, want 0 for future timestamp", count)
		}
	})

	t.Run("CountRevokedSince", func(t *testing.T) {
		store, clients := newStores(t)
		ctx := context.Background()
		seedClient(t, clients, "client-1")

		// Create and revoke a token.
		mt := newTestMachineToken("jti-revcount-1", "client-1")
		if err := store.Save(ctx, mt); err != nil {
			t.Fatalf("save: %v", err)
		}
		if err := store.Revoke(ctx, "jti-revcount-1"); err != nil {
			t.Fatalf("revoke: %v", err)
		}

		// Count since 1 hour ago — should include the revoked token.
		since := time.Now().UTC().Add(-1 * time.Hour).Unix()
		count, err := store.CountRevokedSince(ctx, since)
		if err != nil {
			t.Fatalf("count revoked since: %v", err)
		}
		if count < 1 {
			t.Errorf("count = %d, want >= 1", count)
		}

		// Create a non-revoked token — should not be counted.
		mt2 := newTestMachineToken("jti-revcount-2", "client-1")
		if err := store.Save(ctx, mt2); err != nil {
			t.Fatalf("save mt2: %v", err)
		}
		count2, err := store.CountRevokedSince(ctx, since)
		if err != nil {
			t.Fatalf("count revoked since (2): %v", err)
		}
		if count2 != count {
			t.Errorf("count changed from %d to %d after adding non-revoked token", count, count2)
		}
	})
}
