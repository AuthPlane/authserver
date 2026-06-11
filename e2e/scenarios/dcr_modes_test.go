//go:build e2e

package scenarios

import (
	"net/http"
	"testing"

	"github.com/authplane/authserver/e2e"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/ports/input"
)

func TestDCR_OpenMode(t *testing.T) {
	h := e2e.NewTestHarness(t, e2e.HarnessConfig{
		DCRMode: "open",
		Resources: []config.ResourceConfigUnified{
			{Slug: "test-mcp", URI: "http://localhost:9999", BackendKind: "mint", DisplayName: "test-mcp", Scopes: []config.ScopeConfig{{Name: "tools/echo"}}},
		},
	})

	resp, status := h.RegisterClient(input.RegisterClientRequest{
		RedirectURIs:            []string{"http://localhost:9999/callback"},
		ClientName:              "open-mode-client",
		TokenEndpointAuthMethod: "none",
	})

	if status != http.StatusCreated {
		t.Fatalf("open mode: expected 201, got %d", status)
	}
	if resp == nil || resp.ClientID == "" {
		t.Fatal("open mode: expected client_id in response")
	}
}

func TestDCR_AdminOnlyMode(t *testing.T) {
	h := e2e.NewTestHarness(t, e2e.HarnessConfig{
		DCRMode: "admin_only",
		Resources: []config.ResourceConfigUnified{
			{Slug: "test-mcp", URI: "http://localhost:9999", BackendKind: "mint", DisplayName: "test-mcp", Scopes: []config.ScopeConfig{{Name: "tools/echo"}}},
		},
	})

	_, status := h.RegisterClient(input.RegisterClientRequest{
		RedirectURIs:            []string{"http://localhost:9999/callback"},
		ClientName:              "rejected-client",
		TokenEndpointAuthMethod: "none",
	})

	if status != http.StatusForbidden {
		t.Fatalf("admin_only mode: expected 403, got %d", status)
	}
}

func TestDCR_ApprovedRedirectsMode(t *testing.T) {
	h := e2e.NewTestHarness(t, e2e.HarnessConfig{
		DCRMode:           "approved_redirects",
		ApprovedRedirects: []string{"http://localhost:9999/callback"},
		Resources: []config.ResourceConfigUnified{
			{Slug: "test-mcp", URI: "http://localhost:9999", BackendKind: "mint", DisplayName: "test-mcp", Scopes: []config.ScopeConfig{{Name: "tools/echo"}}},
		},
	})

	// Matching redirect URI → succeeds.
	resp, status := h.RegisterClient(input.RegisterClientRequest{
		RedirectURIs:            []string{"http://localhost:9999/callback"},
		ClientName:              "approved-client",
		TokenEndpointAuthMethod: "none",
	})
	if status != http.StatusCreated {
		t.Fatalf("approved_redirects with matching URI: expected 201, got %d", status)
	}
	if resp == nil || resp.ClientID == "" {
		t.Fatal("approved_redirects: expected client_id in response")
	}

	// Non-matching redirect URI → fails.
	_, status = h.RegisterClient(input.RegisterClientRequest{
		RedirectURIs:            []string{"http://evil.com/callback"},
		ClientName:              "rejected-client",
		TokenEndpointAuthMethod: "none",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("approved_redirects with non-matching URI: expected 400, got %d", status)
	}
}
