package oauth

import (
	"context"
	"net/http"
	"time"
)

// DPoPNonceIssuer issues server nonces for DPoP proof-of-possession (RFC 9449).
// Implemented by output.DPoPNonceStore.
type DPoPNonceIssuer interface {
	IssueNonce(ctx context.Context, ttl time.Duration) (string, error)
}

// DPoPNonceMiddleware injects a fresh DPoP-Nonce header on token endpoint
// responses to requests that present a DPoP proof (RFC 9449 §8). Clients MAY use
// the nonce in subsequent proofs. When require_nonce is true at the service
// layer, proofs without a valid nonce are rejected; this header is how the
// client recovers.
//
// Only requests carrying a DPoP header get a nonce, and that gate is
// load-bearing rather than an optimization. IssueNonce is a durable database
// insert, and this middleware runs BEFORE client authentication and before
// grant dispatch — so issuing unconditionally meant any unauthenticated caller
// could write a row per request with `curl -X POST /oauth/token -d grant_type=x`,
// bounded only by the global rate limiter, against a table with no in-process
// purge. That cost nothing while dpop.enabled defaulted to false and the
// middleware was never installed; enabling DPoP by default made it reachable.
//
// Nothing is lost by the gate: a client that presents no proof is not doing
// DPoP and has no use for a nonce, and a client that must supply one under
// require_nonce is by definition sending a proof.
func DPoPNonceMiddleware(issuer DPoPNonceIssuer, nonceTTL time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("DPoP") != "" {
				// Set before the handler writes, so it rides on the response
				// whether the request succeeds or fails.
				nonce, err := issuer.IssueNonce(r.Context(), nonceTTL)
				if err == nil && nonce != "" {
					w.Header().Set("DPoP-Nonce", nonce)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
