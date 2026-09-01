package static_test

import (
	"context"
	"testing"

	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/ports/output"
)

// Compile-time guard: NewIssuerProvider's return type satisfies the port.
// The pointer-receiver conformance is asserted in the production file
// (issuer_provider.go); this one covers the constructor signature.
var _ output.IssuerProvider = static.NewIssuerProvider("https://x")

func TestIssuerProvider_ReturnsConfiguredValue(t *testing.T) {
	p := static.NewIssuerProvider("https://as.example.com")
	got, err := p.Issuer(context.Background())
	if err != nil {
		t.Fatalf("Issuer: unexpected error: %v", err)
	}
	if got != "https://as.example.com" {
		t.Fatalf("Issuer() = %q, want %q", got, "https://as.example.com")
	}
}

func TestIssuerProvider_IgnoresContext(t *testing.T) {
	p := static.NewIssuerProvider("https://as.example.com")
	type fakeKey struct{}
	ctx := context.WithValue(context.Background(), fakeKey{}, "should-be-ignored")
	got, err := p.Issuer(ctx)
	if err != nil {
		t.Fatalf("Issuer: unexpected error: %v", err)
	}
	if got != "https://as.example.com" {
		t.Fatalf("Issuer() = %q, want %q", got, "https://as.example.com")
	}
}

func TestIssuerProvider_PanicsOnEmptyInput(t *testing.T) {
	// Empty or slash-only inputs must panic at construction time so operator
	// typos are caught at startup rather than silently yielding an empty issuer.
	cases := []struct {
		name  string
		input string
	}{
		{name: "empty string", input: ""},
		{name: "single slash", input: "/"},
		{name: "multiple slashes", input: "///"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("NewIssuerProvider(%q) should panic but did not", tc.input)
				}
			}()
			static.NewIssuerProvider(tc.input)
		})
	}
}

func TestIssuerProvider_TrimsTrailingSlash(t *testing.T) {
	// Match the existing mint_issuer.go:91 trim convention so behavior is identical
	// regardless of which service captures the value.
	// Table covers no-op, single slash, and multiple slashes to guard against
	// accidental swap to strings.TrimSuffix (which only strips one occurrence).
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no trailing slash (no-op)",
			input: "https://as.example.com",
			want:  "https://as.example.com",
		},
		{
			name:  "single trailing slash",
			input: "https://as.example.com/",
			want:  "https://as.example.com",
		},
		{
			name:  "multiple trailing slashes",
			input: "https://as.example.com///",
			want:  "https://as.example.com",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := static.NewIssuerProvider(tc.input)
			got, err := p.Issuer(context.Background())
			if err != nil {
				t.Fatalf("Issuer: unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("Issuer() = %q, want %q", got, tc.want)
			}
		})
	}
}
