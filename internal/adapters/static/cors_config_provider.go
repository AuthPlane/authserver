package static

import (
	"context"

	"github.com/authplane/authserver/internal/ports/output"
)

// Compile-time conformance: CORSConfigProvider satisfies output.CORSConfigProvider.
var _ output.CORSConfigProvider = (*CORSConfigProvider)(nil)

// CORSConfigProvider returns a fixed allowed-origins list captured at
// construction, regardless of ctx. It is the byte-identity-preserving default
// used by cmd/authserver/serve.go: it returns the boot cfg.AllowedOrigins list
// on every call and never errors.
//
// Unlike the other static providers it does NOT panic on an empty list: an
// empty allowlist is a valid configuration meaning "CORS disabled".
type CORSConfigProvider struct {
	origins []string
}

// NewCORSConfigProvider captures a fixed allowed-origins list. It defensively
// copies the slice so a later mutation of the caller's buffer cannot change the
// resolved policy. A nil or empty list is accepted and yields no CORS headers.
func NewCORSConfigProvider(allowedOrigins []string) *CORSConfigProvider {
	origins := append([]string(nil), allowedOrigins...)
	return &CORSConfigProvider{origins: origins}
}

// AllowedOrigins returns the captured allowlist. It copies the slice so a caller
// that mutates the returned list cannot corrupt the provider's stored policy. It
// ignores ctx and never errors.
func (p *CORSConfigProvider) AllowedOrigins(_ context.Context) ([]string, error) {
	return append([]string(nil), p.origins...), nil
}
