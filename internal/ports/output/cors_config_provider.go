package output

import "context"

// CORSConfigProvider supplies the CORS allowed-origins allowlist applicable to
// the request being served — the exact set of origins permitted to make
// browser-based requests to the CORS-eligible endpoints (token, introspection,
// revocation, registration, discovery). The seam is deliberately narrow:
// allowed origins only.
//
// Implementations may resolve the list from configuration, from ctx, or from a
// backing store, and MAY return an error when resolution fails. An empty list
// means no CORS headers are emitted; a single "*" entry allows any origin.
//
// Callers MUST fail closed on error: emit no CORS headers for that request,
// never falling back to a stale or process-wide allowlist. The default static
// provider returns a fixed list captured at boot and never errors.
type CORSConfigProvider interface {
	AllowedOrigins(ctx context.Context) ([]string, error)
}
