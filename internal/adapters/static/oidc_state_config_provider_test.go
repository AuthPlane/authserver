package static

import (
	"context"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/ports/output"
)

func TestOIDCStateConfigProvider_ReturnsConfig(t *testing.T) {
	want := output.OIDCStateConfig{MaxAge: 10 * time.Minute}
	p := NewOIDCStateConfigProvider(want)
	got, err := p.Config(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
