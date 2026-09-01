//go:build e2e

package scenarios

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// registerMachineClientViaDCR registers a client_credentials client through the
// public RFC 7591 endpoint, sending a `scope` member in the body.
//
// The body is raw JSON on purpose: input.RegisterClientRequest has no Scope
// field, so the typed harness helper cannot express the request an operator
// actually sends. Posting the wire form is the only way to observe what the
// server does with a member it does not model.
//
// Returns the credentials plus the decoded 201 body so callers can assert on
// what came back.
func registerMachineClientViaDCR(t *testing.T, h *e2e.TestHarness, scope string) (clientID, clientSecret string, body map[string]any) {
	t.Helper()

	req := map[string]any{
		"client_name":                "dcr-machine-client",
		"grant_types":                []string{"client_credentials"},
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      scope,
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal registration body: %v", err)
	}

	resp, err := http.Post(h.Issuer+"/oauth/register", "application/json", strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("POST /oauth/register: %v", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /oauth/register: expected 201, got %d, body: %s", resp.StatusCode, raw)
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode registration response: %v", err)
	}

	id, _ := body["client_id"].(string)
	secret, _ := body["client_secret"].(string)
	if id == "" || secret == "" {
		t.Fatalf("registration returned no credentials: %s", raw)
	}
	return id, secret, body
}

// TestDCRScopeCeiling_ClientCredentialsDenied is the failure this ticket
// documents. A client registered through open DCR asks for a scope it sent at
// registration time; the AS never stored that scope, so the request is refused
// with invalid_scope and an error_description that names the door the client
// came through and where machine clients are registered instead.
func TestDCRScopeCeiling_ClientCredentialsDenied(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
	}, []string{"tools/echo", "tools/query"})

	clientID, clientSecret, regBody := registerMachineClientViaDCR(t, h, "tools/echo tools/query")

	// 1. The registration succeeded and the scope member vanished.
	if _, present := regBody["scope"]; present {
		t.Errorf("registration response carries a scope member: %v", regBody["scope"])
	}

	// 2. Asking for the scope that was sent at registration is refused.
	oe := h.ClientCredentialsExchangeExpectError(clientID, clientSecret, "tools/echo")
	t.Logf("token endpoint returned %d %s: %s", oe.StatusCode, oe.Error, oe.ErrorDescription)

	if oe.StatusCode != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", oe.StatusCode)
	}
	if oe.Error != "invalid_scope" {
		t.Errorf("error: got %q, want %q", oe.Error, "invalid_scope")
	}
	// The description has to name the registration door specifically — the
	// generic "scope is invalid or not allowed" alone would send a developer
	// hunting through the resource catalog instead of the admin surface.
	// These fragments are pinned deliberately: the unit tests in
	// internal/services/client_credentials_test.go are the canonical pin, and
	// this layer proves the string survives to the wire unmodified.
	for _, want := range []string{
		"created through dynamic registration",
		"user-delegated clients only",
		"pre-registered through the admin API",
	} {
		if !strings.Contains(oe.ErrorDescription, want) {
			t.Errorf("error_description missing %q\ngot: %s", want, oe.ErrorDescription)
		}
	}
	// A DCR client must never be sent to PATCH: that repairs a client which
	// should not have been created for this grant.
	if strings.Contains(oe.ErrorDescription, "PATCH") {
		t.Errorf("error_description offers PATCH to a DCR client\ngot: %s", oe.ErrorDescription)
	}

	// 3. Omitting scope is not refused — it yields a token with no scopes.
	//    The AS does not block this; a resource server enforcing a scope is
	//    what rejects it later, with 403 insufficient_scope.
	tr := h.ClientCredentialsExchange(clientID, clientSecret, "", "")
	if tr.AccessToken == "" {
		t.Fatal("expected a token when scope is omitted")
	}
	if tr.Scope != "" {
		t.Errorf("scope: got %q, want empty", tr.Scope)
	}
}

// TestDCRScopeCeiling_AdminGrantThenSucceeds pins what an operator-granted
// ceiling changes, on its own DCR-registered client — it shares no state with
// the scenario above. Note what this is NOT: a recommended flow. The
// error_description no longer sends a dynamically registered client here — an
// M2M client belongs on the admin surface from the start (POST /admin/clients).
// This exercises the ceiling as the gate and the overreach branch of
// scopeDenialError; it does not endorse register-then-patch.
func TestDCRScopeCeiling_AdminGrantThenSucceeds(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
		EnableAdminAPI:          true,
	}, []string{"tools/echo", "tools/query"})

	clientID, clientSecret, _ := registerMachineClientViaDCR(t, h, "tools/echo tools/query")

	// Same starting point as the denial test.
	oe := h.ClientCredentialsExchangeExpectError(clientID, clientSecret, "tools/echo")
	if oe.Error != "invalid_scope" {
		t.Fatalf("precondition: expected invalid_scope before the admin grant, got %q", oe.Error)
	}

	// 1. Operator grants the scopes over the admin API.
	resp := h.AdminRequest(http.MethodPatch, "/admin/clients/"+clientID, map[string]any{
		"scope": "tools/echo tools/query",
	})
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH /admin/clients/%s: expected 200, got %d, body: %s", clientID, resp.StatusCode, raw)
	}
	// The 200 body is not asserted on: clientView (api/admin/dto.go) has no
	// scope field, so no admin read surface echoes the ceiling back. The token
	// exchange below is the only available proof that the write landed.

	// 2. The exchange that failed a moment ago now succeeds.
	tr := h.ClientCredentialsExchange(clientID, clientSecret, "tools/echo", "")
	if tr.AccessToken == "" {
		t.Fatal("expected non-empty access_token")
	}
	if tr.Scope != "tools/echo" {
		t.Errorf("scope: got %q, want %q", tr.Scope, "tools/echo")
	}
	if tr.TokenType != "Bearer" {
		t.Errorf("token_type: got %q, want Bearer", tr.TokenType)
	}

	// 3. Omitting scope now inherits the full ceiling rather than nothing.
	full := h.ClientCredentialsExchange(clientID, clientSecret, "", "")
	if full.Scope != "tools/echo tools/query" {
		t.Errorf("defaulted scope: got %q, want %q", full.Scope, "tools/echo tools/query")
	}

	// 4. The ceiling is still a ceiling — asking beyond it fails, and with the
	//    overreach branch of scopeDenialError rather than the one that names
	//    the registration door.
	beyond := h.ClientCredentialsExchangeExpectError(clientID, clientSecret, "tools/echo tools/admin")
	if beyond.Error != "invalid_scope" {
		t.Errorf("error: got %q, want invalid_scope", beyond.Error)
	}
	if !strings.Contains(beyond.ErrorDescription, "exceeds the client's registered scopes") {
		t.Errorf("error_description: got %q, want the exceeds-ceiling wording", beyond.ErrorDescription)
	}
}
