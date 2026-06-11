//go:build e2e

package scenarios

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// TestDBOnlyScopeDiscovery verifies the full OAuth flow works when resource
// servers (and their scopes) are registered ONLY via the admin API (database),
// with ZERO static config.
//
// The wellknown handler reads scopes exclusively from the resource_servers
// table (via ResourceListerFunc). This test ensures that path works end-to-end.
func TestDBOnlyScopeDiscovery(t *testing.T) {
	// Create resource server with its scopes.
	rs := e2e.NewMCPResourceServer(t, []string{"tools/echo"})

	// Create harness with NO static resource config; EnableAdminAPI=true
	// so AdminCreateResource (the operator-shaped registration path) is
	// available to the test. The whole point of this scenario is that
	// scopes can flow from the admin API → resources table → discovery
	// metadata, without static YAML.
	h := e2e.NewTestHarness(t, e2e.HarnessConfig{
		EnableAdminAPI: true,
	})
	rs.SetAuthServer(h.Issuer)

	// Register the resource via the public admin API — same surface an
	// operator would use following the docs. Replaces the Gate-0
	// shortcut (h.SeedMintResource → direct resourceStore.Create).
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:        "echo-server",
		DisplayName: "echo-server",
		URI:         rs.URI,
		BackendKind: "mint",
		Scopes:      []e2e.AdminScope{{Name: "tools/echo", Description: "Echo tool"}},
	})

	// Setup user and client.
	h.CreateUser("dbscope@example.com", "password123")
	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)

	// 1. Verify AS metadata includes DB scopes.
	metaResp, err := http.Get(h.Issuer + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("AS metadata request failed: %v", err)
	}
	defer metaResp.Body.Close()

	var meta map[string]any
	json.NewDecoder(metaResp.Body).Decode(&meta)
	scopes, ok := meta["scopes_supported"].([]any)
	if !ok || len(scopes) == 0 {
		t.Fatalf("AS metadata should include DB scopes, got: %v", meta["scopes_supported"])
	}
	found := false
	for _, s := range scopes {
		if s == "tools/echo" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("AS metadata scopes_supported missing tools/echo: %v", scopes)
	}

	// 2. Full OAuth flow: login → authorize → consent → token → call tool.
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)
	tokens := client.FullFlow("dbscope@example.com", "password123", "tools/echo", false)

	if tokens.AccessToken == "" {
		t.Fatal("expected access token")
	}
	if tokens.Scope != "tools/echo" {
		t.Fatalf("expected scope 'tools/echo', got %q", tokens.Scope)
	}

	// 3. JWT claims should have correct audience.
	claims := client.VerifyJWTClaims(tokens.AccessToken)
	if len(claims.Audience) == 0 || claims.Audience[0] != rs.URI {
		t.Fatalf("JWT aud: got %v, want [%s]", claims.Audience, rs.URI)
	}

	// 4. Call tool on resource server — should work.
	status, result := client.CallTool("/tools/echo", tokens.AccessToken, `"db-scope-test"`)
	if status != http.StatusOK {
		t.Fatalf("echo tool: expected 200, got %d, result: %v", status, result)
	}
	if result["result"] != `"db-scope-test"` {
		t.Fatalf("echo tool: unexpected result %v", result["result"])
	}
}
