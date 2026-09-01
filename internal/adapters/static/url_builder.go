package static

import (
	"context"

	"github.com/authplane/authserver/internal/ports/output"
)

// URLBuilder is the OSS impl of output.URLBuilder. It serves everything at the
// root and ignores ctx: Resolve returns the path unchanged (empty mount). The
// Resolve seam exists so an alternative builder can serve the AS under a mount
// path (e.g. a reverse-proxy deployment); the OSS default never does.
type URLBuilder struct{}

// NewURLBuilder returns the root URLBuilder for the single-deployment setup.
func NewURLBuilder() *URLBuilder {
	return &URLBuilder{}
}

// Resolve returns path unchanged — the OSS deployment is served at the root.
// An alternative builder may prepend a mount prefix (e.g. "/api/v2/auth") so
// Resolve(ctx, "/login") -> "/api/v2/auth/login" and Resolve(ctx, "/") ->
// "/api/v2/auth/" (the cookie scope).
func (URLBuilder) Resolve(_ context.Context, path string) (string, error) {
	return path, nil
}

// Compile-time conformance check.
var _ output.URLBuilder = (*URLBuilder)(nil)
