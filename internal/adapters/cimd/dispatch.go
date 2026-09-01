package cimd

import (
	"context"
	"net/http"

	"github.com/authplane/authserver/internal/ssrf"
)

// requireHTTPSKey is a private context key carrying the per-request SSRF policy
// from Fetch down into dispatchTransport.RoundTrip. Unexported type + unique
// zero-size value: no other package can read or clobber it.
type requireHTTPSKey struct{}

// withRequireHTTPS stamps the per-request decision onto the request's context.
// The context is private to each request, so this is the race-free channel for
// per-request state (a struct field would be shared; a header would leak to the
// wire).
func withRequireHTTPS(ctx context.Context, requireHTTPS bool) context.Context {
	return context.WithValue(ctx, requireHTTPSKey{}, requireHTTPS)
}

// dispatchTransport is one http.RoundTripper that routes each request to the
// SSRF-safe or plain transport based on the per-request policy in its context.
//
// Thread safety: safe and plain are assigned once at construction and never
// mutated. They are read-only shared state. RoundTrip only reads them and reads
// req.Context() (private to each request) — no shared mutable state, so it is
// safe for concurrent use without locks, as the RoundTripper contract requires.
type dispatchTransport struct {
	safe  http.RoundTripper // ssrf.NewSafeTransport(): blocks private/reserved IPs
	plain http.RoundTripper // default transport: allows loopback (dev/test)
}

func newDispatchTransport() *dispatchTransport {
	return &dispatchTransport{
		safe:  ssrf.NewSafeTransport(),
		plain: http.DefaultTransport,
	}
}

// RoundTrip implements http.RoundTripper. It delegates to one of the two real
// transports; it never reimplements HTTP and never modifies the request.
func (d *dispatchTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Fail closed: absent policy ⇒ the safe (SSRF-on) transport.
	requireHTTPS, ok := req.Context().Value(requireHTTPSKey{}).(bool)
	if !ok {
		requireHTTPS = true
	}
	if requireHTTPS {
		return d.safe.RoundTrip(req)
	}
	return d.plain.RoundTrip(req)
}
