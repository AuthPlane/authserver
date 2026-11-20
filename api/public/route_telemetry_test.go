package public

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/observability"
)

// NewServer must hand the matched mux pattern to the request span, including
// when a ChainBuilder inserts middleware that replaces the request.
func TestNewServer_SpanNamedByMatchedRoute(t *testing.T) {
	replacing := func(c ChainDeps, inner http.Handler) http.Handler {
		return DefaultChain(c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			inner.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), builderKey{}, true)))
		}))
	}
	for name, build := range map[string]ChainBuilder{"default": nil, "replacing builder": replacing} {
		spans := tracetest.NewSpanRecorder()
		tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
		t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
		obs := observability.NewNoop()
		obs.Tracer = tp.Tracer("test")
		srv := NewServer(context.Background(), config.ServerConfig{Issuer: "https://auth.example.com", Address: ":0"},
			newTestServerDeps(true, build), obs)

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/livez", nil)
		srv.Handler().ServeHTTP(httptest.NewRecorder(), req)

		ended := spans.Ended()
		if len(ended) != 1 {
			t.Fatalf("%s: %d spans, want 1", name, len(ended))
		}
		if got := ended[0].Name(); got != "GET /livez" {
			t.Errorf("%s: span name %q, want the mux pattern", name, got)
		}
	}
}
