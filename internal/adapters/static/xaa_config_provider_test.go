package static

import (
	"context"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/ports/output"
)

func TestXAAConfigProvider_ReturnsConfig(t *testing.T) {
	want := output.XAAConfig{
		Enabled:         true,
		MaxAssertionAge: 5 * time.Minute,
		SubjectMode:     "strict",
		JWKSCacheTTL:    time.Hour,
		RequireResource: true,
		TokenExpiry:     time.Hour,
	}
	p := NewXAAConfigProvider(want)
	got, err := p.Config(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
