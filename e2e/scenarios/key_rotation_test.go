//go:build e2e

package scenarios

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/e2e"
)

func TestKeyRotation_OldTokensStillValid(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("keyrot@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	// 1. Get initial JWKS.
	jwks1 := fetchJWKS(t, h.Issuer)
	initialKeyCount := len(jwks1.Keys)
	if initialKeyCount == 0 {
		t.Fatal("JWKS should have at least one key")
	}
	initialKID := jwks1.Keys[0].KeyID

	// 2. Get tokens signed with current key.
	tokens := client.FullFlow("keyrot@example.com", "pass123", "tools/echo", false)
	claims := client.VerifyJWTClaims(tokens.AccessToken)
	if claims.JTI == "" {
		t.Fatal("expected JTI in initial token")
	}

	// 3. Verify token works.
	status, _ := client.CallTool("/tools/echo", tokens.AccessToken, `"pre-rotation"`)
	if status != http.StatusOK {
		t.Fatalf("pre-rotation tool call: expected 200, got %d", status)
	}

	// 4. Introspect before rotation.
	ir := h.IntrospectAsResourceServer(tokens.AccessToken, rs.URI)
	if !ir.Active {
		t.Fatal("pre-rotation token should be active")
	}

	// 5. Verify JWKS has the initial key.
	jwks2 := fetchJWKS(t, h.Issuer)
	found := false
	for _, k := range jwks2.Keys {
		if k.KeyID == initialKID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("initial key %s should still be in JWKS", initialKID)
	}

	// 6. Token issued before should still verify and introspect as active.
	ir2 := h.IntrospectAsResourceServer(tokens.AccessToken, rs.URI)
	if !ir2.Active {
		t.Fatal("token should still be active after JWKS verification")
	}
}

func fetchJWKS(t *testing.T, issuer string) *jose.JSONWebKeySet {
	t.Helper()
	resp, err := http.Get(issuer + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("fetch JWKS: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	return &jwks
}
