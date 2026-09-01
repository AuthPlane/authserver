package static_test

import (
	"context"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/ports/output"
)

func TestAuditQueryConfigProvider_ReturnsCapturedConfig(t *testing.T) {
	want := output.AuditQueryConfig{
		DefaultLookback: 12 * time.Hour,
		MaxLookback:     365 * 24 * time.Hour,
	}
	p := static.NewAuditQueryConfigProvider(want)
	got, err := p.Config(context.Background())
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if got != want {
		t.Fatalf("Config = %+v, want %+v", got, want)
	}
}

// The provider is read on every audit query, so repeated calls must agree.
// AuditQueryConfig is all value fields, so there is no shared-buffer hazard to
// guard here the way the []byte-keyed providers must.
func TestAuditQueryConfigProvider_Config_IsStableAcrossCalls(t *testing.T) {
	p := static.NewAuditQueryConfigProvider(output.AuditQueryConfig{
		DefaultLookback: 24 * time.Hour,
		MaxLookback:     30 * 24 * time.Hour,
	})
	first, _ := p.Config(context.Background())
	again, _ := p.Config(context.Background())
	if first != again {
		t.Fatalf("Config not stable across calls: %+v then %+v", first, again)
	}
}
