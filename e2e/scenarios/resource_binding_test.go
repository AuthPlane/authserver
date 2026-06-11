//go:build e2e

package scenarios

import (
	"net/http"
	"testing"

	"github.com/authplane/authserver/e2e"
)

func TestResourceBinding_AudMismatch(t *testing.T) {
	scopesA := []string{"tools/echo"}
	scopesB := []string{"tools/echo"}

	// Create harness with two resource servers.
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopesA, scopesB)
	rsA := servers[0]
	rsB := servers[1]

	// Setup.
	h.CreateUser("binding@example.com", "pass123")
	h.RegisterScope(rsA.URI, "tools/echo", "Echo tool A")
	h.RegisterScope(rsB.URI, "tools/echo", "Echo tool B")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)

	// Get token for resource server A.
	clientA := e2e.NewMCPClient(t, h, rsA, clientID, redirectURI)
	tokensA := clientA.FullFlow("binding@example.com", "pass123", "tools/echo", false)

	// Call tool on server A → 200.
	status, _ := clientA.CallTool("/tools/echo", tokensA.AccessToken, `"test"`)
	if status != http.StatusOK {
		t.Fatalf("server A: expected 200, got %d", status)
	}

	// Use same token on server B → 401 (aud mismatch).
	clientB := e2e.NewMCPClient(t, h, rsB, clientID, redirectURI)
	status = clientB.CallToolRaw("/tools/echo", tokensA.AccessToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("server B with server A token: expected 401, got %d", status)
	}
}
