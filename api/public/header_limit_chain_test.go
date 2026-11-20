package public

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/observability"
)

// observedChain builds DefaultChain around mux, wrapped by wrap as a
// distribution's ChainBuilder would, with a text logger, a manual metric
// reader and a span recorder to assert on.
func observedChain(t *testing.T, mux *http.ServeMux, wrap func(http.Handler) http.Handler) (http.Handler, *bytes.Buffer, *sdkmetric.ManualReader, *tracetest.SpanRecorder) {
	t.Helper()
	var logs bytes.Buffer
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })
	spans := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	obs := observability.NewNoop()
	obs.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	obs.Tracer = tp.Tracer("test")
	counter, err := mp.Meter("test").Int64Counter("authserver_http_requests_total")
	if err != nil {
		t.Fatal(err)
	}
	obs.Metrics.HTTPRequestsTotal = counter

	inner := observability.RecordRoute(mux)
	if wrap != nil {
		inner = wrap(inner)
	}
	h := DefaultChain(ChainDeps{Obs: obs, CORS: func(next http.Handler) http.Handler { return next }}, inner)
	return h, &logs, reader, spans
}

// requestSeries returns the method, route and status labels of every series
// recorded on authserver_http_requests_total.
func requestSeries(t *testing.T, reader *sdkmetric.ManualReader) []map[string]string {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var out []map[string]string
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "authserver_http_requests_total" {
				continue
			}
			for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
				method, _ := dp.Attributes.Value(attribute.Key("http.method"))
				route, _ := dp.Attributes.Value(attribute.Key("http.route"))
				code, _ := dp.Attributes.Value(attribute.Key("http.status_code"))
				out = append(out, map[string]string{
					"method": method.AsString(), "route": route.AsString(), "status": code.String(),
				})
			}
		}
	}
	return out
}

// A 431 from the header cap must go through the real chain's telemetry: the
// access log, the cap's own warning, the HTTP request counter with a bounded
// route label, and the request span. A matched route keeps its pattern label.
func TestDefaultChain_HeaderLimitIsObservable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h, logs, reader, spans := observedChain(t, mux, nil)

	ok := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, ok)
	if rec.Code != http.StatusOK {
		t.Fatalf("normal request: status %d", rec.Code)
	}

	big := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/"+strings.Repeat("p", 2000), nil)
	big.Header.Set("Cookie", strings.Repeat("c", shared.MaxRequestHeaderBytes))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, big)
	if rec.Code != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("oversized request: status %d, want 431", rec.Code)
	}

	out := logs.String()
	if !strings.Contains(out, "request headers too large") || !strings.Contains(out, "status=431") {
		t.Fatalf("want the cap warning and a 431 access-log line:\n%s", out)
	}
	if strings.Contains(out, strings.Repeat("p", 300)) || strings.Contains(out, strings.Repeat("c", 100)) {
		t.Fatal("log carries an untruncated path or a header value")
	}

	routes := map[string]string{}
	for _, ser := range requestSeries(t, reader) {
		routes[ser["status"]] = ser["route"]
	}
	if routes["200"] != "GET /healthz" {
		t.Errorf("route label for the matched request = %q, want the mux pattern", routes["200"])
	}
	if routes["431"] != "unmatched" {
		t.Errorf("route label for the 431 = %q, want unmatched", routes["431"])
	}

	found := false
	for _, s := range spans.Ended() {
		for _, e := range s.Events() {
			if e.Name == "request headers too large" {
				found = true
			}
		}
		if len(s.Name()) > 300 {
			t.Errorf("span name is %d bytes; the path must be truncated", len(s.Name()))
		}
	}
	if !found {
		t.Error("no span carries the request-headers-too-large event")
	}
}

// Caller-chosen request fields must not mint metric series or span names: an
// arbitrary method becomes "_OTHER", distinct paths on one route share its
// pattern, and a ChainBuilder middleware that replaces the request does not
// hide the route.
func TestDefaultChain_TelemetryLabelsStayBounded(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth/x/{id}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	replace := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), builderKey{}, true)))
		})
	}
	h, logs, reader, spans := observedChain(t, mux, replace)

	for _, target := range []string{"/oauth/x/123", "/oauth/x/456"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", target, rec.Code)
		}
	}
	for i := range 3 {
		method := "RANDOMMETHOD" + strings.Repeat("Z", 200) + string(rune('a'+i))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), method, "/oauth/x/1", nil))
	}

	series := requestSeries(t, reader)
	if len(series) != 2 {
		t.Fatalf("want 2 series (matched GET, _OTHER), got %d: %v", len(series), series)
	}
	for _, ser := range series {
		switch ser["method"] {
		case http.MethodGet:
			if ser["route"] != "GET /oauth/x/{id}" || ser["status"] != "200" {
				t.Errorf("matched series = %v, want the mux pattern and 200", ser)
			}
		case "_OTHER":
			if ser["route"] != "unmatched" {
				t.Errorf("unknown-method series = %v, want route unmatched", ser)
			}
		default:
			t.Errorf("method label %.40q is not bounded", ser["method"])
		}
	}

	names := map[string]bool{}
	for _, s := range spans.Ended() {
		names[s.Name()] = true
		for _, kv := range s.Attributes() {
			if kv.Key == "http.route" && kv.Value.AsString() != "GET /oauth/x/{id}" && kv.Value.AsString() != "unmatched" {
				t.Errorf("span http.route = %q", kv.Value.AsString())
			}
		}
	}
	if len(names) != 2 || !names["GET /oauth/x/{id}"] || !names["_OTHER"] {
		t.Errorf("span names = %v, want the route pattern and _OTHER", names)
	}
	if strings.Contains(logs.String(), "RANDOMMETHOD") {
		t.Error("access log carries the raw method")
	}
}

type builderKey struct{}
