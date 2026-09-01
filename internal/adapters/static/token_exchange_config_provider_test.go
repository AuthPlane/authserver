package static

import (
	"context"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/ports/output"
)

func TestTokenExchangeConfigProvider_ReturnsConfig(t *testing.T) {
	want := output.TokenExchangeConfig{Enabled: true, AllowSelfExchange: true, MaxChainDepth: 5, TokenExpiry: time.Hour}
	p := NewTokenExchangeConfigProvider(want)
	got, err := p.Config(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
