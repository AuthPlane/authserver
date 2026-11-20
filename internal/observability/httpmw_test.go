package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRequestID_Generated(t *testing.T) {
	mw := NewHTTPMiddleware(NewNoop())
	handler := mw.RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := RequestIDFromContext(r.Context())
		if !ok {
			t.Fatal("expected request_id in context")
		}
		if id == "" {
			t.Fatal("expected non-empty request_id")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("X-Request-ID") == "" {
		t.Fatal("expected X-Request-ID response header")
	}
}

func TestRequestID_Propagated(t *testing.T) {
	mw := NewHTTPMiddleware(NewNoop())
	handler := mw.RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := RequestIDFromContext(r.Context())
		if !ok {
			t.Fatal("expected request_id in context")
		}
		if id != "incoming-req-id" {
			t.Fatalf("expected incoming-req-id, got %s", id)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	req.Header.Set("X-Request-ID", "incoming-req-id")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("X-Request-ID") != "incoming-req-id" {
		t.Fatalf("expected propagated X-Request-ID, got %s", rec.Header().Get("X-Request-ID"))
	}
}

func TestLogging_StatusLevels(t *testing.T) {
	// We can't easily capture slog output from noop logger, but we can verify
	// the middleware doesn't panic and correctly wraps the response writer.
	mw := NewHTTPMiddleware(NewNoop())

	tests := []struct {
		name   string
		status int
	}{
		{"200 OK", http.StatusOK},
		{"404 Not Found", http.StatusNotFound},
		{"500 Server Error", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := mw.Logging()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
			}))

			req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.status {
				t.Fatalf("expected status %d, got %d", tt.status, rec.Code)
			}
		})
	}
}

func TestTracing_SpanCreated(t *testing.T) {
	mw := NewHTTPMiddleware(NewNoop())
	handler := mw.Tracing()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestMetrics_Recorded(t *testing.T) {
	mw := NewHTTPMiddleware(NewNoop())
	handler := mw.Metrics()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestRecover_PanicRecovery(t *testing.T) {
	mw := NewHTTPMiddleware(NewNoop())
	handler := mw.Recover()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	}))

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 after panic, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Internal Server Error") {
		t.Fatalf("expected error body, got %s", rec.Body.String())
	}
}

func TestResponseWriter_CapturesStatus(t *testing.T) {
	rw := newResponseWriter(httptest.NewRecorder())
	rw.WriteHeader(http.StatusNotFound)

	if rw.statusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rw.statusCode)
	}

	// Second WriteHeader should be ignored
	rw.WriteHeader(http.StatusOK)
	if rw.statusCode != http.StatusNotFound {
		t.Fatal("second WriteHeader should not overwrite first")
	}
}

func TestResponseWriter_CapturesBytes(t *testing.T) {
	rw := newResponseWriter(httptest.NewRecorder())
	n, err := rw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Fatalf("expected 5 bytes written, got %d", n)
	}
	if rw.written != 5 {
		t.Fatalf("expected 5 bytes tracked, got %d", rw.written)
	}
}

func TestMiddlewareChain_FullStack(t *testing.T) {
	mw := NewHTTPMiddleware(NewNoop())

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request ID was set
		_, ok := RequestIDFromContext(r.Context())
		if !ok {
			t.Fatal("expected request_id in full middleware chain")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Chain: Recover → RequestID → Tracing → Metrics → Logging → handler
	handler := mw.Recover()(
		mw.RequestID()(
			mw.Tracing()(
				mw.Metrics()(
					mw.Logging()(inner),
				),
			),
		),
	)

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Header().Get("X-Request-ID") == "" {
		t.Fatal("expected X-Request-ID in response")
	}
}

// An unmatched request must not put its path into the metric label: the
// path is caller-chosen, so it would mint series without bound.
func TestRouteHolder_UnmatchedIsConstant(t *testing.T) {
	_, h := withRouteHolder(context.Background())
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/some/path", nil)
	if got := h.route(req); got != "unmatched" {
		t.Fatalf("route = %q, want unmatched", got)
	}
	req.Pattern = "GET /some/{id}"
	if got := h.route(req); got != "GET /some/{id}" {
		t.Fatalf("route = %q, want the mux pattern", got)
	}
}

type replacedKey struct{}

// A middleware between the chain and the mux that replaces the request must
// not hide the route: RecordRoute reports it through the shared holder.
func TestRecordRoute_SurvivesReplacedRequest(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /x/{id}", func(w http.ResponseWriter, _ *http.Request) {})
	replace := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), replacedKey{}, 1)))
		})
	}
	ctx, h := withRouteHolder(context.Background())
	req := httptest.NewRequestWithContext(ctx, "GET", "/x/123", nil)
	replace(RecordRoute(mux)).ServeHTTP(httptest.NewRecorder(), req)
	if got := h.route(req); got != "GET /x/{id}" {
		t.Fatalf("route = %q, want the mux pattern", got)
	}
}

func TestMethodLabel(t *testing.T) {
	for in, want := range map[string]string{
		"GET": "GET", "POST": "POST", "OPTIONS": "OPTIONS", "PATCH": "PATCH",
		"get": "_OTHER", "RANDOM123": "_OTHER", strings.Repeat("M", 4096): "_OTHER",
	} {
		if got := MethodLabel(in); got != want {
			t.Errorf("MethodLabel(%.20q) = %q, want %q", in, got, want)
		}
	}
}

func TestSpanName(t *testing.T) {
	if got := spanName("GET", "GET /healthz"); got != "GET /healthz" {
		t.Errorf("got %q", got)
	}
	if got := spanName("POST", "/token"); got != "POST /token" {
		t.Errorf("got %q", got)
	}
}

func TestTruncateForLog_KeepsUTF8Valid(t *testing.T) {
	s := strings.Repeat("a", 255) + "é" // the 2-byte rune straddles the 256-byte cut
	got := TruncateForLog(s, 256)
	if !utf8.ValidString(got) {
		t.Fatalf("truncation split a rune: %q", got[250:])
	}
	if got != strings.Repeat("a", 255)+"..." {
		t.Fatalf("got %q", got[250:])
	}
	if TruncateForLog("short", 256) != "short" {
		t.Fatal("short strings must be unchanged")
	}
}

func TestValidRequestID(t *testing.T) {
	for id, want := range map[string]bool{
		"":                       false,
		"abc-123_X.y":            true,
		strings.Repeat("a", 128): true,
		strings.Repeat("a", 129): false,
		"has space":              false,
		"kong-uuid#42":           true,
		"b64+/x=":                true,
		"semi;colon":             true,
		"quo\"te":                false,
		"back\\slash":            false,
		"tab\there":              false,
		"\u00e9":                 false,
	} {
		if got := validRequestID(id); got != want {
			t.Errorf("validRequestID(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestRequestID_ReplacesOversizedInboundID(t *testing.T) {
	mw := NewHTTPMiddleware(NewNoop())
	handler := mw.RequestID()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.Header.Set("X-Request-ID", strings.Repeat("a", 10_000))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get("X-Request-ID"); len(got) > 128 || got == "" {
		t.Fatalf("echoed X-Request-ID has %d bytes, want a generated ID", len(got))
	}
}
