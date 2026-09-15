//go:build e2e

package scenarios

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// The 2026-07-28 authorization spec makes Protected Resource Metadata
// normative: MCP servers MUST implement RFC 9728, and clients MUST use it for
// authorization server discovery. Serving it from the AS covers the common case
// where the MCP server is a process the operator cannot add a /.well-known
// route to.
//
// The chain this pins is the one a client actually walks: fetch the document,
// read authorization_servers, and confirm it names an AS whose own discovery
// document is reachable and self-consistent. A PRM naming an unreachable AS is
// worse than no PRM at all — it sends the client somewhere it cannot recover
// from.
func TestPRM_ServedByASAndPointsAtAWorkingAuthorizationServer(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	// The harness registers its resources with slug "mcp-0".
	prmURL := h.Issuer + "/.well-known/oauth-protected-resource/mcp-0"

	resp, err := http.Get(prmURL)
	if err != nil {
		t.Fatalf("GET %s: %v", prmURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 from %s", resp.StatusCode, prmURL)
	}

	var prm struct {
		Resource               string   `json:"resource"`
		AuthorizationServers   []string `json:"authorization_servers"`
		ScopesSupported        []string `json:"scopes_supported"`
		BearerMethodsSupported []string `json:"bearer_methods_supported"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&prm); err != nil {
		t.Fatalf("decode PRM: %v", err)
	}

	if prm.Resource != rs.URI {
		t.Errorf("resource = %q, want the registered resource URI %q", prm.Resource, rs.URI)
	}
	if len(prm.AuthorizationServers) == 0 {
		t.Fatal("authorization_servers is empty; the document exists to carry this field")
	}
	if prm.AuthorizationServers[0] != h.Issuer {
		t.Errorf("authorization_servers[0] = %q, want %q", prm.AuthorizationServers[0], h.Issuer)
	}
	if len(prm.BearerMethodsSupported) != 1 || prm.BearerMethodsSupported[0] != "header" {
		t.Errorf("bearer_methods_supported = %v, want [header]", prm.BearerMethodsSupported)
	}
	if len(prm.ScopesSupported) == 0 {
		t.Error("scopes_supported is empty; the resource has a registered scope")
	}

	// Walk the discovery chain the way a client would: the AS named above must
	// serve a metadata document that identifies itself as that same issuer.
	client := e2e.NewMCPClient(t, h, rs, "", "")
	meta := client.DiscoverASMetadata(prm.AuthorizationServers[0])
	if meta.Issuer != prm.AuthorizationServers[0] {
		t.Errorf("AS metadata issuer = %q, but PRM pointed at %q", meta.Issuer, prm.AuthorizationServers[0])
	}
	if meta.TokenEndpoint == "" {
		t.Error("AS reached via PRM advertises no token endpoint")
	}
}

// An identifier the AS does not know about is a legitimate question. It must
// answer 404 rather than 500 or a stub document, so a client can tell "not this
// server" from "this server is broken".
func TestPRM_UnknownResourceIs404(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{}, []string{"tools/echo"})

	resp, err := http.Get(h.Issuer + "/.well-known/oauth-protected-resource/no-such-resource")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}
