package connectionapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// TestRegisterRoutes_DisabledStub_ReturnsTypedError —. With Connect
// nil (operator opted out), /connect/* routes return a typed
// service_unavailable error pointing at connect.state_secret instead of the
// pre- silent 404 / empty consent_url.
func TestRegisterRoutes_DisabledStub_ReturnsTypedError(t *testing.T) {
	mux := http.NewServeMux()
	sessMW := shared.NewSessionMiddleware(static.NewSessionSecretProvider([]byte(strings.Repeat("k", 32))), static.NewSessionConfigProvider(output.SessionConfig{SameSite: http.SameSiteLaxMode}), "s", false)
	obs := observability.NewNoop()

	RegisterRoutes(mux, Deps{Connect: nil}, sessMW, obs)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/connect/google?return_url=http://x", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got, _ := body["error"].(string); got != "service_unavailable" {
		t.Errorf("error: got %q, want service_unavailable", got)
	}
	desc, _ := body["error_description"].(string)
	if !strings.Contains(desc, "connect.state_secret") {
		t.Errorf("error_description must name the config key, got %q", desc)
	}
	if !strings.Contains(desc, "connect") {
		t.Errorf("error_description must name the feature, got %q", desc)
	}
}
