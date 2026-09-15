package oauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// RFC 9207 Section 2.4 has clients compare iss to the recorded issuer with
// simple string comparison (RFC 3986 Section 6.2.1), and explicitly forbids them
// from applying scheme/host case folding, default-port elision, trailing-slash
// or percent-encoding normalization first. That makes byte-exactness on our side
// load-bearing: any tidying we do here shows up as a mismatch the client cannot
// reconcile, and it fails closed — the code is discarded unredeemed.
//
// These issuers are the shapes most likely to tempt a normalizer.
var issRoundTripCases = []struct {
	name   string
	issuer string
}{
	{"plain https", "https://auth.example.com"},
	{"trailing slash preserved", "https://auth.example.com/"},
	{"explicit default port preserved", "https://auth.example.com:443"},
	{"non-default port", "https://auth.example.com:9000"},
	{"path component preserved", "https://auth.example.com/issuer-a"},
	{"path with trailing slash", "https://auth.example.com/issuer-a/"},
	{"uppercase host preserved", "https://AUTH.example.com"},
	{"percent-encoded path segment preserved", "https://auth.example.com/issuer%2Da"},
}

// redirectLocation drives one of the redirect helpers and returns the parsed
// Location query. It fails the test if the helper did not redirect.
func redirectLocation(t *testing.T, emit func(http.ResponseWriter, *http.Request)) url.Values {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://auth.example.com/oauth/authorize", nil)
	emit(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	return loc.Query()
}

func TestRedirectWithCode_IssRoundTripsVerbatim(t *testing.T) {
	t.Parallel()

	for _, tc := range issRoundTripCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			q := redirectLocation(t, func(w http.ResponseWriter, r *http.Request) {
				redirectWithCode(w, r, "https://client.example.com/callback", "the-code", "the-state", tc.issuer)
			})

			if got := q.Get("iss"); got != tc.issuer {
				t.Errorf("iss = %q, want %q (byte-exact)", got, tc.issuer)
			}
			if got := q.Get("code"); got != "the-code" {
				t.Errorf("code = %q, want %q", got, "the-code")
			}
			if got := q.Get("state"); got != "the-state" {
				t.Errorf("state = %q, want %q", got, "the-state")
			}
		})
	}
}

// The spec requires iss on error responses too, and that is the case most likely
// to be missed: a client MUST NOT act on or display error, error_description or
// error_uri when the issuer does not match, so an error response without iss
// leaves the client no way to attribute it.
func TestRedirectWithError_IssRoundTripsVerbatim(t *testing.T) {
	t.Parallel()

	for _, tc := range issRoundTripCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			q := redirectLocation(t, func(w http.ResponseWriter, r *http.Request) {
				redirectWithError(w, r, "https://client.example.com/callback", "the-state", "access_denied", "user said no", tc.issuer)
			})

			if got := q.Get("iss"); got != tc.issuer {
				t.Errorf("iss = %q, want %q (byte-exact)", got, tc.issuer)
			}
			if got := q.Get("error"); got != "access_denied" {
				t.Errorf("error = %q, want %q", got, "access_denied")
			}
		})
	}
}

// A redirect_uri that already carries query parameters must keep them: iss is
// added to the existing set, never substituted for it.
func TestRedirectWithCode_PreservesExistingRedirectURIQuery(t *testing.T) {
	t.Parallel()

	q := redirectLocation(t, func(w http.ResponseWriter, r *http.Request) {
		redirectWithCode(w, r, "https://client.example.com/callback?flavor=acme", "the-code", "", "https://auth.example.com")
	})

	if got := q.Get("flavor"); got != "acme" {
		t.Errorf("pre-existing redirect_uri query lost: flavor = %q, want %q", got, "acme")
	}
	if got := q.Get("iss"); got != "https://auth.example.com" {
		t.Errorf("iss = %q", got)
	}
	if _, present := q["state"]; present {
		t.Error("empty state must be omitted, not emitted as an empty parameter")
	}
}
