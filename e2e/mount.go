package e2e

import (
	"context"
	"strings"

	"github.com/authplane/authserver/internal/ports/output"
)

// mountURLBuilder is an output.URLBuilder that serves the AS under a path
// prefix, the deployment shape the OSS static.URLBuilder documents as possible
// but does not implement ("an alternative builder may prepend a mount prefix").
//
// It exists so the compliance suite can exercise a mounted deployment, where
// the issuer carries a path component and RFC 8414 Section 3.1 path-insertion
// discovery becomes the shape a conformant MCP client probes first. That
// topology cannot be reached with the root builder, and it is the only one in
// which several discovery requirements have any teeth.
type mountURLBuilder struct{ mount string }

// Resolve prepends the mount to path, preserving the query string
// byte-for-byte per the output.URLBuilder contract: the mount applies to the
// path segment only, and nothing past the first "?" is touched.
func (b mountURLBuilder) Resolve(_ context.Context, path string) (string, error) {
	segment, query, hasQuery := strings.Cut(path, "?")
	resolved := b.mount + segment
	if hasQuery {
		return resolved + "?" + query, nil
	}
	return resolved, nil
}

// Compile-time conformance check.
var _ output.URLBuilder = mountURLBuilder{}
