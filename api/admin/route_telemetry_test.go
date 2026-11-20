package admin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	apiadmin "github.com/authplane/authserver/api/admin"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

// The admin server must hand the matched mux pattern to its request span,
// with and without the rate limiter between the chain and the mux.
func TestNewServer_SpanNamedByMatchedRoute(t *testing.T) {
	for _, rateLimited := range []bool{false, true} {
		spans := tracetest.NewSpanRecorder()
		tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
		t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
		obs := observability.NewNoop()
		obs.Tracer = tp.Tracer("test")

		stores := testdata.SetupTestStores(t)
		adminSvc := services.NewAdminService(stores.Client, stores.User, stores.Token, stores.Audit, obs, nil,
			services.WithMachineTokenStore(stores.MachineToken), services.WithRevocationStore(stores.Revocation))
		cfg := config.AdminConfig{Enabled: true, Address: ":0", APIKey: sysAPIKey}
		if rateLimited {
			cfg.RequestsPerSecond, cfg.Burst = 100, 100
		}
		srv := mustNewServer(t, cfg, adminSvc, obs, apiadmin.OptionalDeps{})

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/admin/clients", nil)
		srv.Handler().ServeHTTP(httptest.NewRecorder(), req)

		ended := spans.Ended()
		if len(ended) != 1 {
			t.Fatalf("rateLimited=%v: %d spans, want 1", rateLimited, len(ended))
		}
		if got := ended[0].Name(); got != "GET /admin/clients" {
			t.Errorf("rateLimited=%v: span name %q, want the mux pattern", rateLimited, got)
		}
	}
}
