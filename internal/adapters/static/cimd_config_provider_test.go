package static

import (
	"context"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/ports/output"
)

func TestCIMDConfigProvider_ReturnsConfig(t *testing.T) {
	want := output.CIMDConfig{Enabled: true, RequireHTTPS: true, CacheTTL: 5 * time.Minute, FetchTimeout: 10 * time.Second}
	p := NewCIMDConfigProvider(want)
	got, err := p.Config(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
