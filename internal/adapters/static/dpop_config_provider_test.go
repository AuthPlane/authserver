package static

import (
	"context"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/ports/output"
)

func TestDPoPConfigProvider_ReturnsConfig(t *testing.T) {
	want := output.DPoPConfig{Enabled: true, NonceTTL: 60 * time.Second, ProofLifetime: 60 * time.Second, RequireNonce: true}
	p := NewDPoPConfigProvider(want)
	got, err := p.Config(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
