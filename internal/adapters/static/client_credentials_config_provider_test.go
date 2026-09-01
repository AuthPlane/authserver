package static

import (
	"context"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/ports/output"
)

func TestClientCredentialsConfigProvider_ReturnsConfig(t *testing.T) {
	want := output.ClientCredentialsConfig{Enabled: true, TokenExpiry: 90 * time.Minute}
	p := NewClientCredentialsConfigProvider(want)
	got, err := p.Config(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
