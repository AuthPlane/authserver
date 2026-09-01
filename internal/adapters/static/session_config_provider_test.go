package static

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/ports/output"
)

func TestSessionConfigProvider_ReturnsConfig(t *testing.T) {
	want := output.SessionConfig{
		MaxAge:     24 * time.Hour,
		Secure:     true,
		SameSite:   http.SameSiteLaxMode,
		FailClosed: true,
	}
	p := NewSessionConfigProvider(want)
	got, err := p.Config(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
