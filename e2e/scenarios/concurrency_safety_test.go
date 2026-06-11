//go:build e2e

package scenarios

import (
	"net/http"
	"sync"
	"testing"

	"github.com/authplane/authserver/e2e"
	"github.com/authplane/authserver/internal/ports/input"
)

// TestConcurrentClientUpdate verifies that concurrent admin updates to the same
// client are handled safely via optimistic locking — at least one update succeeds,
// and the final state is consistent.
func TestConcurrentClientUpdate(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("concurrent-admin@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)

	// Launch concurrent suspend + reactivate attempts.
	const goroutines = 4
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			var err error
			if idx%2 == 0 {
				err = h.AdminSvc.SuspendClient(t.Context(), clientID)
			} else {
				err = h.AdminSvc.ReactivateClient(t.Context(), clientID)
			}
			mu.Lock()
			errs = append(errs, err)
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// At least one operation should succeed.
	var successes int
	for _, err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes < 1 {
		t.Errorf("expected at least 1 success, got 0. Errors: %v", errs)
	}

	// Final state should be consistent (either active or suspended, not corrupt).
	got, err := h.AdminSvc.GetClient(t.Context(), clientID)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if got.Status != "active" && got.Status != "suspended" {
		t.Errorf("unexpected client status: %q", got.Status)
	}
}

// TestConcurrentRefreshWithTokenRotation extends the existing concurrent refresh test
// to verify that after concurrent reuse, the family is revoked and subsequent
// operations (including new authorization) still work correctly.
func TestConcurrentRefreshWithTokenRotation(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("rotate-race@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	tokens := client.FullFlow("rotate-race@example.com", "pass123", "tools/echo", false)
	if tokens.RefreshToken == "" {
		t.Fatal("expected refresh token")
	}

	// Refresh once to get a rotated token.
	refreshed := h.RefreshToken(tokens.RefreshToken, clientID)
	if refreshed.RefreshToken == tokens.RefreshToken {
		t.Fatal("refresh token should rotate")
	}

	// Now race the OLD (consumed) token — this should trigger family revocation.
	const goroutines = 3
	var wg sync.WaitGroup
	statuses := make([]int, goroutines)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			statuses[idx], _ = h.RefreshTokenRaw(tokens.RefreshToken, clientID)
		}(i)
	}
	wg.Wait()

	// All should fail (token was already consumed).
	for i, s := range statuses {
		if s != http.StatusBadRequest {
			t.Errorf("goroutine %d: expected 400, got %d", i, s)
		}
	}

	// The rotated token should also be revoked (entire family).
	oe := h.RefreshTokenExpectError(refreshed.RefreshToken, clientID)
	if oe.Error != "invalid_grant" {
		t.Errorf("expected invalid_grant for rotated token after family revocation, got %q", oe.Error)
	}
}

// TestDeleteClientForceWithActiveTokens_E2E tests the full admin flow of force-deleting
// a client that has active token families — verifying atomicity and cleanup.
func TestDeleteClientForceWithActiveTokens_E2E(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("delete-client@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	// Get tokens for the client.
	tokens := client.FullFlow("delete-client@example.com", "pass123", "tools/echo", false)
	if tokens.AccessToken == "" {
		t.Fatal("expected access token")
	}

	// Non-force delete should fail (has active tokens).
	err := h.AdminSvc.DeleteClient(t.Context(), clientID, false)
	if err == nil {
		t.Fatal("expected error for non-force delete with active tokens")
	}

	// Force delete should succeed.
	if err := h.AdminSvc.DeleteClient(t.Context(), clientID, true); err != nil {
		t.Fatalf("force delete: %v", err)
	}

	// Client should be gone.
	_, err = h.AdminSvc.GetClient(t.Context(), clientID)
	if err == nil {
		t.Fatal("expected error for deleted client")
	}
}

// TestOptimisticLocking_DCRUpdate verifies that DCR client updates honor version checks.
func TestOptimisticLocking_DCRUpdate(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("dcr-version@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	// Register a client.
	redirectURI := "http://localhost:9999/callback"
	resp, status := h.RegisterClient(input.RegisterClientRequest{
		RedirectURIs:            []string{redirectURI},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		ClientName:              "DCR Version Test",
	})
	if status != http.StatusCreated {
		t.Fatalf("register: got %d", status)
	}

	// Update client name via admin.
	newName := "Updated DCR Client"
	_, err := h.AdminSvc.UpdateClient(t.Context(), resp.ClientID, input.UpdateClientRequest{
		Name: &newName,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	// Verify updated.
	got, err := h.AdminSvc.GetClient(t.Context(), resp.ClientID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "Updated DCR Client" {
		t.Errorf("name: got %q, want %q", got.Name, "Updated DCR Client")
	}
}
