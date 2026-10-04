package idpjwks

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestDiscoverJWKSUri_SSRFBlocksPrivateIPs(t *testing.T) {
	// DiscoverJWKSUri creates an SSRF-safe client that blocks private IPs.
	// Test servers run on 127.0.0.1, which is a private IP, so we verify
	// that the SSRF protection correctly rejects connections to localhost.
	_, err := DiscoverJWKSUri(context.Background(), "https://127.0.0.1:1234")
	if err == nil {
		t.Fatal("expected error (SSRF protection blocks localhost), got nil")
	}
	if !strings.Contains(err.Error(), "SSRF protection") {
		t.Fatalf("error = %v, want an SSRF refusal", err)
	}
}

func TestDiscoverJWKSUri_InvalidURL(t *testing.T) {
	_, err := DiscoverJWKSUri(context.Background(), "not-a-url")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

// TestDiscoverJWKSUri_SSRFBlocksCGNAT pins the second call site. DiscoverJWKSUri
// builds its own client, so it needs its own assertion — the audit confirmed
// both the fetch and the discovery step ran under the weak predicate.
func TestDiscoverJWKSUri_SSRFBlocksCGNAT(t *testing.T) {
	_, err := DiscoverJWKSUri(context.Background(), "https://100.64.7.7")
	if err == nil {
		t.Fatal("expected SSRF refusal for CGNAT issuer, got nil")
	}
	if !strings.Contains(err.Error(), "SSRF protection") {
		t.Fatalf("error = %v, want an SSRF refusal", err)
	}
}

// TestDiscoverJWKSUri_EmitsSpan pins that discovery runs under an
// IDPJWKS.Discover span resolved from the global tracer provider, and that a
// refused fetch marks it as an error.
func TestDiscoverJWKSUri_EmitsSpan(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})

	if _, err := DiscoverJWKSUri(context.Background(), "https://127.0.0.1:1234"); err == nil {
		t.Fatal("expected SSRF refusal, got nil")
	}

	spans := exporter.GetSpans()
	if len(spans) != 1 || spans[0].Name != "IDPJWKS.Discover" {
		t.Fatalf("spans = %+v, want exactly one IDPJWKS.Discover", spans)
	}
	if spans[0].Status.Code != codes.Error {
		t.Errorf("span status = %v, want Error", spans[0].Status.Code)
	}
	found := false
	for _, kv := range spans[0].Attributes {
		if kv.Key == "issuer" && kv.Value.AsString() == "https://127.0.0.1:1234" {
			found = true
		}
	}
	if !found {
		t.Errorf("span missing issuer attribute: %v", spans[0].Attributes)
	}
}
