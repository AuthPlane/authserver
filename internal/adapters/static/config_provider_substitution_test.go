package static

import (
	"context"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/ports/output"
)

// Each case proves a custom value flows through the seam, distinct from any
// boot default — the motivating "stricter staging" example.
// These exercise the Test-B substitution path for the behavior-knob providers.

func TestSubstitution_DPoPStricter(t *testing.T) {
	p := NewDPoPConfigProvider(output.DPoPConfig{Enabled: true, RequireNonce: true, ProofLifetime: 10 * time.Second})
	got, err := p.Config(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.RequireNonce || got.ProofLifetime != 10*time.Second {
		t.Fatalf("substitution not honored: %+v", got)
	}
}

func TestSubstitution_ShorterClientCredentialsTTL(t *testing.T) {
	p := NewClientCredentialsConfigProvider(output.ClientCredentialsConfig{TokenExpiry: 30 * time.Second})
	got, err := p.Config(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.TokenExpiry != 30*time.Second {
		t.Fatalf("substitution not honored: %+v", got)
	}
}

func TestSubstitution_StricterOAuthRequireScope(t *testing.T) {
	p := NewOAuthConfigProvider(output.OAuthConfig{RequireScope: true})
	got, err := p.Config(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.RequireScope {
		t.Fatalf("substitution not honored: %+v", got)
	}
}

func TestSubstitution_ShorterSessionMaxAge(t *testing.T) {
	p := NewSessionConfigProvider(output.SessionConfig{MaxAge: 8 * time.Hour})
	got, err := p.Config(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.MaxAge != 8*time.Hour {
		t.Fatalf("substitution not honored: %+v", got)
	}
}

func TestSubstitution_ShorterOIDCStateMaxAge(t *testing.T) {
	p := NewOIDCStateConfigProvider(output.OIDCStateConfig{MaxAge: 2 * time.Minute})
	got, err := p.Config(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.MaxAge != 2*time.Minute {
		t.Fatalf("substitution not honored: %+v", got)
	}
}
