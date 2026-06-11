//go:build e2e

package scenarios

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// POST /admin/clients must reject grant_types that aren't enabled at
// runtime. Without this, an operator who omitted
// AUTHPLANE_CLIENT_CREDENTIALS_ENABLED would happily land status=active
// clients that can never get a token.
func TestAdmin_CreateClient_GrantNotEnabled_Rejected(t *testing.T) {
	// EnableClientCredentials defaults to false → harness mirrors
	// AUTHPLANE_CLIENT_CREDENTIALS_ENABLED unset.
	h := e2e.NewTestHarness(t, e2e.HarnessConfig{
		EnableAdminAPI: true,
	})

	body := map[string]any{
		"client_name":                "CC Client",
		"grant_types":                []string{"client_credentials"},
		"token_endpoint_auth_method": "client_secret_post",
	}
	resp := h.AdminRequest("POST", "/admin/clients", body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400, got %d; body=%s", resp.StatusCode, raw)
	}
	raw, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(raw), "client_credentials") {
		t.Errorf("body should name the offending grant: %s", raw)
	}
	if !strings.Contains(string(raw), "AUTHPLANE_CLIENT_CREDENTIALS_ENABLED") {
		t.Errorf("body should name the env var: %s", raw)
	}
}

// Same guarantee for the public DCR path. Without the runtime check
// DCR also leaves status=active clients with grants the AS can't honor.
func TestDCR_RegisterClient_GrantNotEnabled_Rejected(t *testing.T) {
	h := e2e.NewTestHarness(t, e2e.HarnessConfig{})

	body, _ := json.Marshal(map[string]any{
		"client_name":                "CC DCR Client",
		"grant_types":                []string{"client_credentials"},
		"token_endpoint_auth_method": "client_secret_post",
	})
	resp, err := http.Post(h.Issuer+"/oauth/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /oauth/register: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400, got %d; body=%s", resp.StatusCode, raw)
	}
	raw, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(raw), "client_credentials") {
		t.Errorf("body should name the offending grant: %s", raw)
	}
	if !strings.Contains(string(raw), "AUTHPLANE_CLIENT_CREDENTIALS_ENABLED") {
		t.Errorf("body should name the env var: %s", raw)
	}
}

// When client_credentials IS enabled, admin client creation continues
// to work — the runtime check must not regress the ordinary
// confidential-client path.
func TestAdmin_CreateClient_GrantEnabled_Accepted(t *testing.T) {
	h := e2e.NewTestHarness(t, e2e.HarnessConfig{
		EnableAdminAPI:          true,
		EnableClientCredentials: true,
	})

	body := map[string]any{
		"client_name":                "CC Client",
		"grant_types":                []string{"client_credentials"},
		"token_endpoint_auth_method": "client_secret_post",
	}
	resp := h.AdminRequest("POST", "/admin/clients", body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 201, got %d; body=%s", resp.StatusCode, raw)
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.ClientID == "" {
		t.Error("client_id should be set when grant is enabled")
	}
}
