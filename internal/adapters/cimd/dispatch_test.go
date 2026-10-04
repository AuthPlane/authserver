package cimd

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// recordingRT records which transport was selected and returns a minimal response.
type recordingRT struct {
	name string
	hit  *string
}

func (r recordingRT) RoundTrip(_ *http.Request) (*http.Response, error) {
	*r.hit = r.name
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
}

// TestDispatchTransport_RoutesByContext verifies dispatchTransport routes to the
// filtering or non-filtering transport from the per-request context value — and
// crucially fails closed to the filtering one when the context carries no policy
// (the branch Fetch never exercises because it always stamps the value).
func TestDispatchTransport_RoutesByContext(t *testing.T) {
	var hit string
	d := &dispatchTransport{
		strict:     recordingRT{name: "strict", hit: &hit},
		permissive: recordingRT{name: "permissive", hit: &hit},
	}

	tests := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{"bare context fails closed to strict", context.Background(), "strict"},
		{"AllowPrivate=false routes to strict", withAllowPrivate(context.Background(), false), "strict"},
		{"AllowPrivate=true routes to permissive", withAllowPrivate(context.Background(), true), "permissive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hit = ""
			req, err := http.NewRequestWithContext(tt.ctx, http.MethodGet, "https://example.com", http.NoBody)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			resp, err := d.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			_ = resp.Body.Close()
			if hit != tt.want {
				t.Errorf("routed to %q, want %q", hit, tt.want)
			}
		})
	}
}

// The scheme of the request must not influence transport selection: that is the
// coupling this change removes, and nothing but the address policy may decide.
func TestDispatchTransport_IgnoresScheme(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			var hit string
			d := &dispatchTransport{
				strict:     recordingRT{name: "strict", hit: &hit},
				permissive: recordingRT{name: "permissive", hit: &hit},
			}
			req, err := http.NewRequestWithContext(
				withAllowPrivate(context.Background(), false),
				http.MethodGet, scheme+"://example.com", http.NoBody)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			resp, err := d.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			_ = resp.Body.Close()
			if hit != "strict" {
				t.Errorf("scheme %s routed to %q, want strict", scheme, hit)
			}
		})
	}
}

// TestDispatchTransport_EmitsSpan verifies each round trip runs under a
// CIMD.Dispatch span carrying the address policy and the response status, and
// that a transport failure marks the span as an error.
func TestDispatchTransport_EmitsSpan(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	var hit string
	d := newDispatchTransport(tp.Tracer("test"))
	d.strict = recordingRT{name: "strict", hit: &hit}
	d.permissive = failingRT{}

	req, _ := http.NewRequestWithContext(withAllowPrivate(context.Background(), false),
		http.MethodGet, "https://example.com", http.NoBody)
	resp, err := d.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	_ = resp.Body.Close()

	req, _ = http.NewRequestWithContext(withAllowPrivate(context.Background(), true),
		http.MethodGet, "https://example.com", http.NoBody)
	resp, err = d.RoundTrip(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected the failing transport's error, got nil")
	}

	spans := exporter.GetSpans()
	if len(spans) != 2 {
		t.Fatalf("got %d spans, want 2", len(spans))
	}
	for _, s := range spans {
		if s.Name != "CIMD.Dispatch" {
			t.Errorf("span name = %q, want CIMD.Dispatch", s.Name)
		}
	}
	if spans[0].Status.Code == codes.Error {
		t.Errorf("successful dispatch span marked Error")
	}
	if !hasAttr(spans[0], "http.status_code", attribute.IntValue(http.StatusOK)) {
		t.Errorf("successful span missing http.status_code=200: %v", spans[0].Attributes)
	}
	if spans[1].Status.Code != codes.Error {
		t.Errorf("failed dispatch span status = %v, want Error", spans[1].Status.Code)
	}
	if !hasAttr(spans[1], "allow_private", attribute.BoolValue(true)) {
		t.Errorf("failed span missing allow_private=true: %v", spans[1].Attributes)
	}
}

// TestDispatchTransport_NilTracerFallsBack pins that a transport built without
// a tracer (as the struct-literal tests above do) still round-trips.
func TestDispatchTransport_NilTracerFallsBack(t *testing.T) {
	var hit string
	d := &dispatchTransport{strict: recordingRT{name: "strict", hit: &hit}, permissive: recordingRT{name: "permissive", hit: &hit}}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", http.NoBody)
	resp, err := d.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip with nil tracer: %v", err)
	}
	_ = resp.Body.Close()
}

type failingRT struct{}

func (failingRT) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("dial refused")
}

func hasAttr(span tracetest.SpanStub, key string, want attribute.Value) bool {
	for _, kv := range span.Attributes {
		if string(kv.Key) == key && kv.Value == want {
			return true
		}
	}
	return false
}
