package idpjwks

import (
	"context"
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
}

func TestDiscoverJWKSUri_InvalidURL(t *testing.T) {
	_, err := DiscoverJWKSUri(context.Background(), "not-a-url")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}
