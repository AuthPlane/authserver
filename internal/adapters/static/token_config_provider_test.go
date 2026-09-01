package static

import (
	"context"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/ports/output"
)

func TestTokenConfigProvider_ReturnsConfig(t *testing.T) {
	want := output.TokenConfig{AccessTokenExpiry: 15 * time.Minute, RefreshTokenExpiry: 7 * 24 * time.Hour}
	p := NewTokenConfigProvider(want)
	got, err := p.Config(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
