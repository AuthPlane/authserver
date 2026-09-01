package static

import (
	"context"
	"slices"
	"sync"

	"github.com/authplane/authserver/internal/ports/output"
)

// Compile-time conformance: DCRModeProvider satisfies output.DCRModeProvider.
var _ output.DCRModeProvider = (*DCRModeProvider)(nil)

// DCRModeProvider returns the same configured DCR mode for every call,
// regardless of ctx. It is the process-global default used by
// cmd/authserver/serve.go. The mode is mutable at runtime via Set (the admin
// DCR settings endpoint), so access is guarded by a mutex: a single provider
// instance is shared across DCRService and CIMDService and read concurrently
// by registration requests while the admin handler may be writing.
type DCRModeProvider struct {
	mu                sync.RWMutex
	mode              string
	approvedRedirects []string
}

// NewDCRModeProvider builds a DCRModeProvider seeded with the static config
// mode and approved redirects.
func NewDCRModeProvider(mode string, approvedRedirects []string) *DCRModeProvider {
	return &DCRModeProvider{
		mode:              mode,
		approvedRedirects: approvedRedirects,
	}
}

// Get returns the configured DCR mode and approved redirects. Ignores ctx. Always returns a nil error.
//
// ApprovedRedirects is cloned so callers never alias the provider's backing
// array: today Set only updates Mode, but cloning keeps Get safe if a future
// Set mutates the slice while another goroutine holds the returned value.
func (p *DCRModeProvider) Get(_ context.Context) (output.DCRMode, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return output.DCRMode{
		Mode:              p.mode,
		ApprovedRedirects: slices.Clone(p.approvedRedirects),
	}, nil
}

// Set updates the DCR mode at runtime. Ignores ctx. Always returns a nil error.
//
// Only mode.Mode is applied; mode.ApprovedRedirects is intentionally ignored.
// The admin runtime control (DCRService.SetMode → DCR settings endpoint) only
// toggles the mode, so the approved-redirects list configured at startup is
// preserved rather than being wiped to the zero value on every mode change.
func (p *DCRModeProvider) Set(_ context.Context, mode output.DCRMode) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.mode = mode.Mode
	return nil
}
