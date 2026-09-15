package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// countingNonceIssuer records how many nonces were minted. IssueNonce is a
// durable database insert in every real implementation, so the count is the
// thing under test, not the header.
type countingNonceIssuer struct{ calls int32 }

func (c *countingNonceIssuer) IssueNonce(_ context.Context, _ time.Duration) (string, error) {
	atomic.AddInt32(&c.calls, 1)
	return "nonce-value", nil
}

// The middleware runs before client authentication and before grant dispatch,
// and IssueNonce writes a durable row. Issuing unconditionally let any
// unauthenticated caller write a row per request against a table with no
// in-process purge. Only a request actually doing DPoP needs a nonce.
func TestDPoPNonceMiddleware_OnlyIssuesForRequestsCarryingAProof(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		dpopHeader string
		wantCalls  int32
		wantHeader bool
	}{
		{"no DPoP header — unauthenticated junk request", "", 0, false},
		{"empty DPoP header", "", 0, false},
		{"DPoP proof present", "eyJhbGciOiJFUzI1NiJ9.e30.sig", 1, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			issuer := &countingNonceIssuer{}
			var reached bool
			h := DPoPNonceMiddleware(issuer, time.Minute)(http.HandlerFunc(
				func(w http.ResponseWriter, _ *http.Request) {
					reached = true
					w.WriteHeader(http.StatusOK)
				},
			))

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/oauth/token", nil)
			if tc.dpopHeader != "" {
				req.Header.Set("DPoP", tc.dpopHeader)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if got := atomic.LoadInt32(&issuer.calls); got != tc.wantCalls {
				t.Errorf("IssueNonce called %d time(s), want %d — each call is a durable row", got, tc.wantCalls)
			}
			if hasHeader := rec.Header().Get("DPoP-Nonce") != ""; hasHeader != tc.wantHeader {
				t.Errorf("DPoP-Nonce header present = %v, want %v", hasHeader, tc.wantHeader)
			}
			// The gate must never affect request handling.
			if !reached {
				t.Error("the wrapped handler was not reached")
			}
		})
	}
}

// A repeated unauthenticated request must not accumulate rows.
func TestDPoPNonceMiddleware_UnauthenticatedFloodWritesNothing(t *testing.T) {
	t.Parallel()

	issuer := &countingNonceIssuer{}
	h := DPoPNonceMiddleware(issuer, time.Minute)(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadRequest) },
	))

	for range 100 {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/oauth/token", nil)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	if got := atomic.LoadInt32(&issuer.calls); got != 0 {
		t.Errorf("100 unauthenticated requests minted %d nonce(s), want 0", got)
	}
}
