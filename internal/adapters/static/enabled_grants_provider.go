package static

import (
	"context"
	"slices"

	"github.com/authplane/authserver/internal/ports/output"
)

// EnabledGrantsProvider returns a fixed set of enabled grant types captured at
// construction. It performs no I/O and never changes at runtime.
type EnabledGrantsProvider struct {
	grants []string
}

// NewEnabledGrantsProvider captures the boot-time enabled-grant set.
func NewEnabledGrantsProvider(grants []string) *EnabledGrantsProvider {
	return &EnabledGrantsProvider{grants: grants}
}

// Get returns a clone so callers never alias the provider's backing array.
func (p *EnabledGrantsProvider) Get(_ context.Context) ([]string, error) {
	return slices.Clone(p.grants), nil
}

var _ output.EnabledGrantsProvider = (*EnabledGrantsProvider)(nil)
