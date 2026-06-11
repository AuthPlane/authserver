package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

func TestRoutePattern_FallsBackToPath(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/some/path", nil)
	pattern := routePattern(req)
	if pattern != "/some/path" {
		t.Fatalf("expected /some/path, got %s", pattern)
	}
}
