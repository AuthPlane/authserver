package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// gateFakeIntrospect records whether the introspection provider was invoked so
// the gating tests can assert the runtime gate short-circuits before it.
type gateFakeIntrospect struct{ called bool }

func (f *gateFakeIntrospect) IntrospectToken(_ context.Context, _ input.IntrospectRequest) (*input.IntrospectResponse, error) {
	f.called = true
	return &input.IntrospectResponse{Active: false}, nil
}

type gateOAuthCfg struct {
	cfg output.OAuthConfig
	err error
}

func (g gateOAuthCfg) Config(context.Context) (output.OAuthConfig, error) { return g.cfg, g.err }

func newIntrospectFormRequest() *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth/introspect", strings.NewReader("token=abc"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestIntrospectGating_Disabled_Returns404(t *testing.T) {
	fake := &gateFakeIntrospect{}
	h := &introspectHandler{
		introspect:  fake,
		oauthConfig: gateOAuthCfg{cfg: output.OAuthConfig{IntrospectionEnabled: false}},
		obs:         observability.NewNoop(),
	}

	rec := httptest.NewRecorder()
	h.handleIntrospect(rec, newIntrospectFormRequest())

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (introspection disabled must match an unregistered route)", rec.Code)
	}
	if fake.called {
		t.Error("introspection provider must not be invoked when disabled")
	}
}

func TestIntrospectGating_Enabled_Serves(t *testing.T) {
	fake := &gateFakeIntrospect{}
	h := &introspectHandler{
		introspect:  fake,
		oauthConfig: gateOAuthCfg{cfg: output.OAuthConfig{IntrospectionEnabled: true}},
		obs:         observability.NewNoop(),
	}

	rec := httptest.NewRecorder()
	h.handleIntrospect(rec, newIntrospectFormRequest())

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 when introspection enabled", rec.Code)
	}
	if !fake.called {
		t.Error("introspection provider must be invoked when enabled")
	}
}

func TestIntrospectGating_ProviderError_Returns404(t *testing.T) {
	fake := &gateFakeIntrospect{}
	h := &introspectHandler{
		introspect:  fake,
		oauthConfig: gateOAuthCfg{err: errors.New("config boom")},
		obs:         observability.NewNoop(),
	}

	rec := httptest.NewRecorder()
	h.handleIntrospect(rec, newIntrospectFormRequest())

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (config error degrades to disabled)", rec.Code)
	}
	if fake.called {
		t.Error("introspection provider must not be invoked on config error")
	}
}

func TestIntrospectGating_NilProvider_Serves(t *testing.T) {
	fake := &gateFakeIntrospect{}
	h := &introspectHandler{introspect: fake, obs: observability.NewNoop()}

	rec := httptest.NewRecorder()
	h.handleIntrospect(rec, newIntrospectFormRequest())

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (nil provider preserves pre-seam always-served behavior)", rec.Code)
	}
}
