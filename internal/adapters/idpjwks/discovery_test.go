package idpjwks

import (
	"context"
	"strings"
	"testing"
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
