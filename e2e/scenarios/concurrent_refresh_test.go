//go:build e2e

package scenarios

import (
	"net/http"
	"sync"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// TestConcurrentRefresh_AtomicConsumption verifies that when multiple goroutines
// use the same refresh token simultaneously, at most one succeeds and the token
// family is revoked due to reuse detection.
func TestConcurrentRefresh_AtomicConsumption(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("concurrent@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	tokens := client.FullFlow("concurrent@example.com", "pass123", "tools/echo", false)
	if tokens.RefreshToken == "" {
		t.Fatal("expected refresh token")
	}

	// Launch concurrent refresh attempts with the SAME token.
	const goroutines = 5
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

	// Count successes and failures.
	var successes, failures int
	for _, s := range statuses {
		switch s {
		case http.StatusOK:
			successes++
		case http.StatusBadRequest:
			failures++
		default:
			t.Errorf("unexpected status: %d", s)
		}
	}

	// At most 1 should succeed (atomic consumption). 0 is possible if family
	// revocation from a losing goroutine beats the winning goroutine's family check.
	if successes > 1 {
		t.Errorf("expected at most 1 success, got %d", successes)
	}

	// All remaining should be failures.
	if successes+failures != goroutines {
		t.Errorf("expected %d total responses, got %d successes + %d failures", goroutines, successes, failures)
	}

	// After the race, the family should be revoked. A fresh refresh with the
	// original token must fail.
	oe := h.RefreshTokenExpectError(tokens.RefreshToken, clientID)
	if oe.Error != "invalid_grant" {
		t.Errorf("expected invalid_grant after concurrent reuse, got %q", oe.Error)
	}
}
