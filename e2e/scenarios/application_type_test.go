//go:build e2e

package scenarios

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// registerRaw POSTs a client-registration body and returns the status and the
// decoded response, driving the public endpoint rather than the service behind
// it — which is what Gate 0 requires of e2e tests, and also the only level at
// which the wire member name is actually proven.
func registerRaw(t *testing.T, h *e2e.TestHarness, body string) (int, map[string]any) {
	t.Helper()

	resp, err := http.Post(h.Issuer+"/oauth/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /oauth/register: %v", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var decoded map[string]any
	_ = json.Unmarshal(raw, &decoded)
	return resp.StatusCode, decoded
}

// SEP-837. MCP clients must declare application_type at registration: omitting
// it defaults to "web" under OpenID Connect, and an OIDC-conformant AS refuses
// a "web" client the http://localhost and http://127.0.0.1 redirect URIs that
// desktop apps, mobile apps and CLI tools depend on. We used to discard the
// member entirely, so a native client had no way to say what it was.
func TestDCR_ApplicationType_EchoedInRegistrationResponse(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{}, []string{"tools/echo"})

	for _, want := range []string{"native", "web"} {
		t.Run(want, func(t *testing.T) {
			status, got := registerRaw(t, h, fmt.Sprintf(`{
				"redirect_uris": ["http://127.0.0.1:3000/callback"],
				"client_name": "app-%s",
				"token_endpoint_auth_method": "none",
				"application_type": %q
			}`, want, want))

			if status != http.StatusCreated {
				t.Fatalf("status = %d, want 201 (body: %v)", status, got)
			}
			// RFC 7591 §3.2.1 returns the registered metadata. A client that
			// sent a member and got nothing back reads that as rejection.
			if got["application_type"] != want {
				t.Errorf("application_type = %v, want %q", got["application_type"], want)
			}
		})
	}
}

// Omitting the member must still register — the spec puts the obligation on
// clients, and refusing everything that predates it would break far more than
// it fixed. The response states the default explicitly so the client learns
// what it got.
func TestDCR_ApplicationType_OmittedEchoesTheOIDCDefault(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{}, []string{"tools/echo"})

	status, got := registerRaw(t, h, `{
		"redirect_uris": ["https://app.example.com/callback"],
		"client_name": "legacy-app",
		"token_endpoint_auth_method": "none"
	}`)

	if status != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body: %v)", status, got)
	}
	if got["application_type"] != "web" {
		t.Errorf("application_type = %v, want the OIDC default \"web\"", got["application_type"])
	}
}

func TestDCR_ApplicationType_UnknownValueRejected(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{}, []string{"tools/echo"})

	status, got := registerRaw(t, h, `{
		"redirect_uris": ["https://app.example.com/callback"],
		"client_name": "bad-app",
		"token_endpoint_auth_method": "none",
		"application_type": "desktop"
	}`)

	if status == http.StatusCreated {
		t.Fatalf("an unknown application_type must not register: %v", got)
	}
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", status)
	}
}
