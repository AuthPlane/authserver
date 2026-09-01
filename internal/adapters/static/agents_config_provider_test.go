package static

import (
	"context"
	"testing"

	"github.com/authplane/authserver/internal/ports/output"
)

func TestAgentsConfigProvider_ReturnsConfig(t *testing.T) {
	want := output.AgentsConfig{EnableJWKSListing: true}
	p := NewAgentsConfigProvider(want)
	got, err := p.Config(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
