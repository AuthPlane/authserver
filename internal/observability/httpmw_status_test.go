package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// newRecordingMiddleware returns an HTTPMiddleware whose tracer exports every
// span synchronously into the returned in-memory exporter.
func newRecordingMiddleware(t *testing.T) (*HTTPMiddleware, *tracetest.InMemoryExporter) {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	p := NewNoop()
	p.Tracer = tp.Tracer("test")
	return NewHTTPMiddleware(p), exp
}

func TestTracing_SpanStatusByResponseCode(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		wantCode  codes.Code
		wantDescr string
	}{
		{"200 stays unset", http.StatusOK, codes.Unset, ""},
		{"404 stays unset", http.StatusNotFound, codes.Unset, ""},
		{"500 is an error", http.StatusInternalServerError, codes.Error, "Internal Server Error"},
		{"503 is an error", http.StatusServiceUnavailable, codes.Error, "Service Unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mw, exp := newRecordingMiddleware(t)
			handler := mw.Tracing()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
			}))

			req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
			handler.ServeHTTP(httptest.NewRecorder(), req)

			spans := exp.GetSpans()
			if len(spans) != 1 {
				t.Fatalf("expected 1 span, got %d", len(spans))
			}
			if got := spans[0].Status.Code; got != tc.wantCode {
				t.Fatalf("status code = %v, want %v", got, tc.wantCode)
			}
			if got := spans[0].Status.Description; got != tc.wantDescr {
				t.Fatalf("status description = %q, want %q", got, tc.wantDescr)
			}
		})
	}
}

// A panicking handler must still end its span as a 500 with the route, so
// panics show in trace error filters (Recover, outside, writes the 500).
func TestTracing_PanicEndsSpanAsServerError(t *testing.T) {
	mw, exp := newRecordingMiddleware(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /boom", func(http.ResponseWriter, *http.Request) { panic("boom") })
	h := mw.Recover()(mw.Tracing()(mw.Metrics()(RecordRoute(mux))))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/boom", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", rec.Code)
	}
	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("%d spans, want 1", len(spans))
	}
	s := spans[0]
	if s.Name != "GET /boom" || s.Status.Code != codes.Error {
		t.Fatalf("span %q status %v, want GET /boom with Error", s.Name, s.Status.Code)
	}
	var status int64
	for _, kv := range s.Attributes {
		if kv.Key == "http.status_code" {
			status = kv.Value.AsInt64()
		}
	}
	if status != http.StatusInternalServerError {
		t.Fatalf("http.status_code = %d, want 500", status)
	}
}
