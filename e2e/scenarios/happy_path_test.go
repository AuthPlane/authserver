//go:build e2e

package scenarios

import (
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

func TestHappyPath(t *testing.T) {
	scopes := []string{"tools/echo", "tools/db_query"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	// Setup: create user and register scopes.
	h.CreateUser("alice@example.com", "password123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")
	h.RegisterScope(rs.URI, "tools/db_query", "Database query tool")

	// Register client via DCR.
	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)

	// Create MCP client.
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	// 1. Discover PRM.
	issuer := client.DiscoverPRM()
	if issuer != h.Issuer {
		t.Fatalf("PRM issuer mismatch: got %s, want %s", issuer, h.Issuer)
	}

	// 2. Discover AS metadata.
	meta := client.DiscoverASMetadata(issuer)
	if meta.Issuer != h.Issuer {
		t.Fatalf("AS metadata issuer mismatch: got %s, want %s", meta.Issuer, h.Issuer)
	}

	// 3. Full flow: login → authorize → consent → token.
	tokens := client.FullFlow("alice@example.com", "password123", "tools/echo tools/db_query", false)

	if tokens.AccessToken == "" {
		t.Fatal("expected access token")
	}
	if tokens.RefreshToken == "" {
		t.Fatal("expected refresh token")
	}
	if tokens.TokenType != "Bearer" {
		t.Fatalf("expected Bearer token type, got %q", tokens.TokenType)
	}
	gotScopes := strings.Split(tokens.Scope, " ")
	wantScopes := strings.Split("tools/echo tools/db_query", " ")
	sort.Strings(gotScopes)
	sort.Strings(wantScopes)
	if !reflect.DeepEqual(gotScopes, wantScopes) {
		t.Fatalf("expected scopes %v, got %v", wantScopes, gotScopes)
	}

	// 4. Call echo tool with access token.
	status, result := client.CallTool("/tools/echo", tokens.AccessToken, `"hello MCP"`)
	if status != http.StatusOK {
		t.Fatalf("echo tool: expected 200, got %d, result: %v", status, result)
	}
	if result["result"] != `"hello MCP"` {
		t.Fatalf("echo tool: unexpected result %v", result["result"])
	}

	// 5. Call db_query tool.
	status, _ = client.CallTool("/tools/db_query", tokens.AccessToken, `{}`)
	if status != http.StatusOK {
		t.Fatalf("db_query tool: expected 200, got %d", status)
	}

	// 6. Verify JWT claims.
	claims := client.VerifyJWTClaims(tokens.AccessToken)
	if claims.Issuer != h.Issuer {
		t.Fatalf("JWT iss: got %s, want %s", claims.Issuer, h.Issuer)
	}
	if claims.ClientID != clientID {
		t.Fatalf("JWT client_id: got %s, want %s", claims.ClientID, clientID)
	}
	if len(claims.Audience) == 0 || claims.Audience[0] != rs.URI {
		t.Fatalf("JWT aud: got %v, want [%s]", claims.Audience, rs.URI)
	}
	gotClaimScopes := strings.Split(claims.Scope, " ")
	sort.Strings(gotClaimScopes)
	if !reflect.DeepEqual(gotClaimScopes, wantScopes) {
		t.Fatalf("JWT scope: got %v, want %v", gotClaimScopes, wantScopes)
	}
	if claims.Subject == "" {
		t.Fatal("JWT sub should not be empty")
	}
	if claims.JTI == "" {
		t.Fatal("JWT jti should not be empty")
	}
	if claims.Expiry == 0 {
		t.Fatal("JWT exp should not be zero")
	}
}
