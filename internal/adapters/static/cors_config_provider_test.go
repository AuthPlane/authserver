package static_test

import (
	"context"
	"testing"

	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/ports/output"
)

// Compile-time guard: NewCORSConfigProvider's return type satisfies the port.
var _ output.CORSConfigProvider = static.NewCORSConfigProvider(nil)

func TestCORSConfigProvider_ReturnsConfiguredOrigins(t *testing.T) {
	p := static.NewCORSConfigProvider([]string{"https://a.example.com", "https://b.example.com"})
	got, err := p.AllowedOrigins(context.Background())
	if err != nil {
		t.Fatalf("AllowedOrigins: unexpected error: %v", err)
	}
	want := []string{"https://a.example.com", "https://b.example.com"}
	if len(got) != len(want) {
		t.Fatalf("AllowedOrigins() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("AllowedOrigins()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCORSConfigProvider_EmptyIsValid(t *testing.T) {
	// An empty allowlist means "CORS disabled" — it must NOT panic (unlike the
	// issuer/session-secret static providers, where empty is an operator typo).
	for _, in := range [][]string{nil, {}} {
		p := static.NewCORSConfigProvider(in)
		got, err := p.AllowedOrigins(context.Background())
		if err != nil {
			t.Fatalf("AllowedOrigins: unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("AllowedOrigins() = %v, want empty", got)
		}
	}
}

func TestCORSConfigProvider_IgnoresContext(t *testing.T) {
	p := static.NewCORSConfigProvider([]string{"https://a.example.com"})
	type fakeKey struct{}
	ctx := context.WithValue(context.Background(), fakeKey{}, "should-be-ignored")
	got, err := p.AllowedOrigins(ctx)
	if err != nil {
		t.Fatalf("AllowedOrigins: unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "https://a.example.com" {
		t.Fatalf("AllowedOrigins() = %v, want [https://a.example.com]", got)
	}
}

func TestCORSConfigProvider_DefensiveCopyOnInput(t *testing.T) {
	// Mutating the caller's buffer after construction must not change the policy.
	in := []string{"https://a.example.com"}
	p := static.NewCORSConfigProvider(in)
	in[0] = "https://evil.example.com"
	got, _ := p.AllowedOrigins(context.Background())
	if got[0] != "https://a.example.com" {
		t.Fatalf("input mutation leaked into provider: got %q", got[0])
	}
}

func TestCORSConfigProvider_DefensiveCopyOnOutput(t *testing.T) {
	// Mutating a returned slice must not corrupt the stored policy.
	p := static.NewCORSConfigProvider([]string{"https://a.example.com"})
	first, _ := p.AllowedOrigins(context.Background())
	first[0] = "https://evil.example.com"
	second, _ := p.AllowedOrigins(context.Background())
	if second[0] != "https://a.example.com" {
		t.Fatalf("output mutation leaked into provider: got %q", second[0])
	}
}
