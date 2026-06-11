//go:build e2e

package scenarios

import (
	"net/http"
	"testing"

	"github.com/authplane/authserver/e2e"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/ports/input"
)

// TestDCR_MissingRedirectURIs verifies that DCR rejects requests without redirect_uris.
func TestDCR_MissingRedirectURIs(t *testing.T) {
	h := e2e.NewTestHarness(t, e2e.HarnessConfig{
		DCRMode: "open",
		Resources: []config.ResourceConfigUnified{
			{Slug: "test", URI: "http://localhost:9999", BackendKind: "mint", DisplayName: "test", Scopes: []config.ScopeConfig{{Name: "tools/echo"}}},
		},
	})

	_, status := h.RegisterClient(input.RegisterClientRequest{
		RedirectURIs:            nil, // Missing
		ClientName:              "no-redirect",
		TokenEndpointAuthMethod: "none",
	})

	if status != http.StatusBadRequest {
		t.Fatalf("missing redirect_uris: expected 400, got %d", status)
	}
}

// TestDCR_FragmentInRedirectURI verifies that redirect URIs containing
// fragments are rejected per RFC 6749 §3.1.2.
func TestDCR_FragmentInRedirectURI(t *testing.T) {
	h := e2e.NewTestHarness(t, e2e.HarnessConfig{
		DCRMode: "open",
		Resources: []config.ResourceConfigUnified{
			{Slug: "test", URI: "http://localhost:9999", BackendKind: "mint", DisplayName: "test", Scopes: []config.ScopeConfig{{Name: "tools/echo"}}},
		},
	})

	_, status := h.RegisterClient(input.RegisterClientRequest{
		RedirectURIs:            []string{"http://localhost:9999/callback#fragment"},
		ClientName:              "fragment-client",
		TokenEndpointAuthMethod: "none",
	})

	if status != http.StatusBadRequest {
		t.Fatalf("fragment in redirect_uri: expected 400, got %d", status)
	}
}

// TestDCR_InvalidGrantType verifies that DCR rejects unsupported grant types.
func TestDCR_InvalidGrantType(t *testing.T) {
	h := e2e.NewTestHarness(t, e2e.HarnessConfig{
		DCRMode: "open",
		Resources: []config.ResourceConfigUnified{
			{Slug: "test", URI: "http://localhost:9999", BackendKind: "mint", DisplayName: "test", Scopes: []config.ScopeConfig{{Name: "tools/echo"}}},
		},
	})

	_, status := h.RegisterClient(input.RegisterClientRequest{
		RedirectURIs:            []string{"http://localhost:9999/callback"},
		ClientName:              "bad-grant-client",
		GrantTypes:              []string{"implicit"},
		TokenEndpointAuthMethod: "none",
	})

	if status != http.StatusBadRequest {
		t.Fatalf("invalid grant_type 'implicit': expected 400, got %d", status)
	}
}

// TestDCR_ResponseContainsClientID verifies the DCR response includes
// all required fields per RFC 7591 §3.2.1.
func TestDCR_ResponseContainsClientID(t *testing.T) {
	h := e2e.NewTestHarness(t, e2e.HarnessConfig{
		DCRMode: "open",
		Resources: []config.ResourceConfigUnified{
			{Slug: "test", URI: "http://localhost:9999", BackendKind: "mint", DisplayName: "test", Scopes: []config.ScopeConfig{{Name: "tools/echo"}}},
		},
	})

	resp, status := h.RegisterClient(input.RegisterClientRequest{
		RedirectURIs:            []string{"http://localhost:9999/callback"},
		ClientName:              "full-response-client",
		TokenEndpointAuthMethod: "none",
	})

	if status != http.StatusCreated {
		t.Fatalf("expected 201, got %d", status)
	}
	if resp.ClientID == "" {
		t.Error("response missing client_id")
	}
	if resp.ClientName != "full-response-client" {
		t.Errorf("client_name: got %q, want %q", resp.ClientName, "full-response-client")
	}
}

// TestDCR_ConfidentialClient_ReturnsSecret verifies that registering a
// confidential client returns a client_secret.
func TestDCR_ConfidentialClient_ReturnsSecret(t *testing.T) {
	h := e2e.NewTestHarness(t, e2e.HarnessConfig{
		DCRMode: "open",
		Resources: []config.ResourceConfigUnified{
			{Slug: "test", URI: "http://localhost:9999", BackendKind: "mint", DisplayName: "test", Scopes: []config.ScopeConfig{{Name: "tools/echo"}}},
		},
	})

	resp, status := h.RegisterClient(input.RegisterClientRequest{
		RedirectURIs:            []string{"http://localhost:9999/callback"},
		ClientName:              "secret-client",
		TokenEndpointAuthMethod: "client_secret_post",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})

	if status != http.StatusCreated {
		t.Fatalf("expected 201, got %d", status)
	}
	if resp.ClientSecret == "" {
		t.Error("confidential client response missing client_secret")
	}
	if resp.TokenEndpointAuthMethod != "client_secret_post" {
		t.Errorf("auth_method: got %q, want client_secret_post", resp.TokenEndpointAuthMethod)
	}
}
