package cimd

import (
	"context"
	"net/http"

	"github.com/authplane/authserver/internal/ssrf"
)

// allowPrivateKey is a private context key carrying the per-request address
// policy from Fetch down into dispatchTransport.RoundTrip. Unexported type +
// unique zero-size value: no other package can read or clobber it.
type allowPrivateKey struct{}

// withAllowPrivate stamps the per-request decision onto the request's context.
// The context is private to each request, so this is the race-free channel for
// per-request state (a struct field would be shared; a header would leak to the
// wire).
func withAllowPrivate(ctx context.Context, allow bool) context.Context {
	return context.WithValue(ctx, allowPrivateKey{}, allow)
}

// dispatchTransport is one http.RoundTripper that routes each request to the
// filtering or non-filtering transport based on the per-request address policy
// in its context. The request's scheme plays no part in that choice: scheme
// enforcement is a separate control, applied earlier and on the URL.
//
// Both transports come from ssrf.NewSafeTransport, so the two paths share this
// repo's timeout settings and differ only in whether resolved addresses are
// checked. Neither is http.DefaultTransport, so neither honors HTTP_PROXY —
// see NewSafeTransport for why a proxy and this filter cannot coexist.
//
// Thread safety: strict and permissive are assigned once at construction and
// never mutated. They are read-only shared state. RoundTrip only reads them and
// reads req.Context() (private to each request) — no shared mutable state, so it
// is safe for concurrent use without locks, as the RoundTripper contract
// requires.
type dispatchTransport struct {
	strict     http.RoundTripper // refuses private/reserved addresses
	permissive http.RoundTripper // same transport, address filter off
}

func newDispatchTransport() *dispatchTransport {
	return &dispatchTransport{
		strict:     ssrf.NewSafeTransport(),
		permissive: ssrf.NewSafeTransport(ssrf.AllowPrivate()),
	}
}

// RoundTrip implements http.RoundTripper. It delegates to one of the two real
// transports; it never reimplements HTTP and never modifies the request.
func (d *dispatchTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Fail closed: absent policy ⇒ the filtering transport.
	allowPrivate, ok := req.Context().Value(allowPrivateKey{}).(bool)
	if !ok || !allowPrivate {
		return d.strict.RoundTrip(req)
	}
	return d.permissive.RoundTrip(req)
}
