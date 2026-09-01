//go:build integration

package public_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apipublic "github.com/authplane/authserver/api/public"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

// newURLBuilderIdentityServer wires the default shape with an explicit
// static URLBuilder. It mirrors newIdentityServer (oidc_provider_identity_test.go)
// but keeps the helper local so this byte-identity test stays self-contained.
func newURLBuilderIdentityServer(t *testing.T, oidcCfg config.OIDCConfig) *httptest.Server {
	t.Helper()
	obs := observability.NewNoop()
	stores := testdata.SetupTestStores(t)
	authSvc := services.NewUserAuthService(stores.User, obs, nil)
	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:    testCORS(),
		Auth:                  authSvc,
		LoginDisplay:          static.NewLoginDisplayProvider(oidcCfg),
		URLs:                  static.NewURLBuilder(),
		SessionSecretProvider: testSessionSecret(),
		SessionConfigProvider: testSessionConfig(),
		SessionCookie:         apipublic.SessionCookie{Name: "authserver_session"},
	}, obs)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// TestLoginHTML_OIDCStartURL_ByteIdentity asserts that the rendered /login
// HTML contains the exact substring `href="/oidc/start?redirect=%2F"` when a
// static URLBuilder is wired — byte-for-byte equal to the pre-F0-12
// hardcoded emission. The redirect parameter is `/` URL-query-escaped to %2F.
func TestLoginHTML_OIDCStartURL_ByteIdentity(t *testing.T) {
	ts := newURLBuilderIdentityServer(t, config.OIDCConfig{
		Enabled:        true,
		DisplayName:    "Test IdP",
		RedirectURI:    "https://as.example.com/oidc/callback",
		ShowLocalLogin: true,
	})

	// Request /login with redirect=/ so the OIDC start link encodes the
	// slash as %2F via template.URLQueryEscaper — matches the byte-identity
	// claim "/oidc/start?redirect=%2F" from the F0-12 plan.
	resp, err := http.Get(ts.URL + "/login?redirect=/")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	html := string(body)

	const want = `href="/oidc/start?redirect=%2F"`
	if !strings.Contains(html, want) {
		t.Fatalf("HTML does not contain byte-identical OIDC start link %q.\nFragment around /oidc/start:\n%s",
			want, extractAround(html, "/oidc/start", 80))
	}
}

// TestLoginHTML_NoOIDC_BuilderNotCalled is a secondary guard: when OIDC is
// disabled at the resolver level (DisplayName empty), the /login HTML must
// not advertise the OIDC start link. This indirectly verifies the URLBuilder
// is only invoked when DisplayName != "" — otherwise the body would still
// carry the link.
func TestLoginHTML_NoOIDC_BuilderNotCalled(t *testing.T) {
	ts := newURLBuilderIdentityServer(t, config.OIDCConfig{
		Enabled:        true,
		DisplayName:    "",
		ShowLocalLogin: true,
	})

	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	html := string(body)

	if strings.Contains(html, "/oidc/start") {
		t.Fatalf("HTML should not advertise /oidc/start when DisplayName is empty.\nFragment around /oidc/start:\n%s",
			extractAround(html, "/oidc/start", 80))
	}
}

// extractAround returns up to `width` bytes around the first occurrence of
// `needle` in `s`, for debugging assertion failures without flooding output.
func extractAround(s, needle string, width int) string {
	i := strings.Index(s, needle)
	if i < 0 {
		return "(not present)"
	}
	start := i - width
	if start < 0 {
		start = 0
	}
	end := i + len(needle) + width
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}
