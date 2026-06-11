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

// DPoPNonceMiddleware injects a fresh DPoP-Nonce header on every token endpoint
// response (RFC 9449 §8). Clients MAY use this nonce in subsequent DPoP proofs.
// When require_nonce is true at the service layer, proofs without a valid nonce
// are rejected; the nonce in this header allows the client to recover.
func DPoPNonceMiddleware(issuer DPoPNonceIssuer, nonceTTL time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Issue a fresh nonce and set it in the response header.
			// The header is set before the handler writes the response,
			// so it's included regardless of success or error.
			nonce, err := issuer.IssueNonce(r.Context(), nonceTTL)
			if err == nil && nonce != "" {
				w.Header().Set("DPoP-Nonce", nonce)
			}
			next.ServeHTTP(w, r)
		})
	}
}
