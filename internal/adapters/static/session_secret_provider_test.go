package static

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestSessionSecretProvider_ReturnsCapturedSecret(t *testing.T) {
	secret := []byte(strings.Repeat("k", 32))
	p := NewSessionSecretProvider(secret)

	got, err := p.Secret(context.Background())
	if err != nil {
		t.Fatalf("Secret returned error: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("Secret = %q, want %q", got, secret)
	}

	// Stable across calls — same backing slice, no copy.
	got2, _ := p.Secret(context.Background())
	if &got[0] != &got2[0] {
		t.Fatal("Secret returned a different backing array; expected the captured slice without copy")
	}
}
