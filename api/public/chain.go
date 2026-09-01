package public

import (
	"net/http"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/observability"
)

// ChainDeps are the inputs NewServer resolves for the middleware chain and hands
// to the ChainBuilder.
//
// It exists so the chain can grow new inputs without breaking a distribution's
// builder: a new middleware that needs a new dependency adds a field here and is
// consumed inside DefaultChain, leaving every ChainBuilder signature untouched.
type ChainDeps struct {
	// Obs is the observability provider backing Recover/RequestID/Tracing/
	// Metrics/Logging.
	Obs *observability.Provider

	// Secure reports whether HTTPS is enforced, which gates the HSTS header.
	Secure bool

	// CORS is the per-request CORS middleware, already bound to the server's
	// CORSConfigProvider.
	CORS func(http.Handler) http.Handler
}

// ChainBuilder composes the server's middleware chain around inner — the routed
// handler (rate limiter, then mux). It returns the handler NewServer serves.
//
// A nil builder means DefaultChain. A builder is expected to compose AROUND
// DefaultChain rather than replace it:
//
//	deps.BuildChain = func(c public.ChainDeps, inner http.Handler) http.Handler {
//		return public.DefaultChain(c, myMiddleware(inner))
//	}
//
// Composing this way is what keeps a distribution correct over time: middleware
// it inserts sits INSIDE the chain, so a response it writes without delegating to
// next still carries CORS and security headers and is recovered, traced, metered
// and logged. Restating the chain instead of calling DefaultChain would leave the
// copy to drift silently the next time the chain changes.
//
// Wrapping the RESULT of DefaultChain places middleware above SecurityHeaders and
// Recover, outside panic safety, and is almost never what a caller wants.
type ChainBuilder func(ChainDeps, http.Handler) http.Handler

// DefaultChain is the server's middleware composition:
//
//	SecurityHeaders → Recover → RequestID → CORS → Tracing → Metrics → Logging → inner
//
// It is exported so a distribution can build on it instead of restating it; the
// order, and the invariant that SecurityHeaders and Recover wrap everything else,
// stay owned here.
func DefaultChain(c ChainDeps, inner http.Handler) http.Handler {
	obsMW := observability.NewHTTPMiddleware(c.Obs)
	return shared.SecurityHeaders(c.Secure)(
		obsMW.Recover()(
			obsMW.RequestID()(
				c.CORS(
					obsMW.Tracing()(
						obsMW.Metrics()(
							obsMW.Logging()(inner),
						),
					),
				),
			),
		),
	)
}
