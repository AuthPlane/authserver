package static_test

import (
	"context"
	"sync"
	"testing"

	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/ports/output"
)

// Compile-time guard: the constructor's return type satisfies the port.
var _ output.DCRModeProvider = static.NewDCRModeProvider("open", nil)

func TestDCRModeProvider_ReturnsConfiguredValues(t *testing.T) {
	approved := []string{"https://app.example.com/callback"}
	p := static.NewDCRModeProvider("approved_redirects", approved)

	got, err := p.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if got.Mode != "approved_redirects" {
		t.Errorf("Mode: got %q, want %q", got.Mode, "approved_redirects")
	}
	if len(got.ApprovedRedirects) != 1 || got.ApprovedRedirects[0] != approved[0] {
		t.Errorf("ApprovedRedirects: got %v, want %v", got.ApprovedRedirects, approved)
	}
}

// Set toggles the mode but must preserve the approved-redirects list seeded at
// construction — the admin runtime control only carries the mode, so a mode
// change must not wipe the configured allowlist.
func TestDCRModeProvider_SetPreservesApprovedRedirects(t *testing.T) {
	approved := []string{"https://app.example.com/callback"}
	p := static.NewDCRModeProvider("approved_redirects", approved)

	if err := p.Set(context.Background(), output.DCRMode{Mode: "open"}); err != nil {
		t.Fatalf("Set: unexpected error: %v", err)
	}

	got, _ := p.Get(context.Background())
	if got.Mode != "open" {
		t.Errorf("Mode after Set: got %q, want %q", got.Mode, "open")
	}
	if len(got.ApprovedRedirects) != 1 || got.ApprovedRedirects[0] != approved[0] {
		t.Errorf("ApprovedRedirects after Set: got %v, want %v (must be preserved)", got.ApprovedRedirects, approved)
	}
}

// TestDCRModeProvider_ConcurrentGetSet exercises the mutex that guards the
// runtime-mutable mode. A single provider is shared across DCRService and
// CIMDService in serve.go: the admin DCR endpoint calls Set while registration
// requests call Get. Run under -race to catch a missing lock.
func TestDCRModeProvider_ConcurrentGetSet(t *testing.T) {
	p := static.NewDCRModeProvider("open", []string{"https://app.example.com/callback"})
	ctx := context.Background()

	var wg sync.WaitGroup
	const goroutines = 8
	const iterations = 500

	for i := 0; i < goroutines; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, _ = p.Get(ctx)
			}
		}()
		go func(id int) {
			defer wg.Done()
			mode := "open"
			if id%2 == 0 {
				mode = "admin_only"
			}
			for j := 0; j < iterations; j++ {
				_ = p.Set(ctx, output.DCRMode{Mode: mode})
			}
		}(i)
	}
	wg.Wait()
}
