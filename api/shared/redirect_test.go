package shared

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authplane/authserver/internal/ports/output"
)

// Destinations SafeRedirect has always classified this way, across the
// rewrite. These rows are invariants: a change here is a regression, not a
// decision.
//
// That claim is about THIS table only. Reclassifications live in
// TestSafeRedirect_ReclassifiedByTheRewrite, and also — inherently — in
// TestSafeRedirect_RejectsEveryControlByteAnywhere, which is reclassified end
// to end, and in the non-position-1 rows of
// TestSafeRedirect_RejectsBackslashInPath. Loosening either of those breaks a
// decision the CHANGELOG records, not a long-standing guarantee.
func TestSafeRedirect_AcceptedAndRejectedDestinations(t *testing.T) {
	const fallback = "/"
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", fallback},
		{"absolute https", "https://evil.com", fallback},
		{"absolute http", "http://evil.com", fallback},
		{"scheme-relative authority", "//evil.com", fallback},
		// Three or more leading slashes leave url.Parse reporting Host "" —
		// the authority between the second and third slash is empty — so the
		// parse layer does not cover them. Browsers do: WHATWG's
		// special-authority-ignore-slashes state consumes the whole run, and
		// the next segment becomes the host.
		{"three leading slashes", "///evil.com", fallback},
		{"four leading slashes", "////evil.com", fallback},
		{"leading slashes then backslash", `//\evil.com`, fallback},
		{"backslash authority", `/\evil.com`, fallback},
		{"slash then backslash authority", `/\/evil.com`, fallback},
		{"unrooted", "evil.com", fallback},
		{"opaque scheme", "javascript:alert(1)", fallback},
		{"rooted path", "/dashboard", "/dashboard"},
		{"rooted path with query", "/a/b?c=d", "/a/b?c=d"},
		{"escaped query preserved byte-for-byte", "/oauth/authorize?client_id=x&scope=a%20b", "/oauth/authorize?client_id=x&scope=a%20b"},
		{"fragment preserved", "/dashboard#frag", "/dashboard#frag"},
		{"encoded percent preserved", "/50%25off", "/50%25off"},
		{"invalid escape in query preserved", "/a?b=%zz", "/a?b=%zz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SafeRedirect(tc.in, fallback); got != tc.want {
				t.Errorf("SafeRedirect(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Targets the rewrite deliberately reclassified. Each row is a decision
// recorded in the CHANGELOG, not an invariant — which is exactly why it needs
// pinning: an unpinned reclassification is one a later refactor reverts in
// silence, and the accepted rows below are reverted by nothing more exotic
// than restoring a blanket `strings.Contains(path, "://")` test.
func TestSafeRedirect_ReclassifiedByTheRewrite(t *testing.T) {
	const fallback = "/"
	cases := []struct {
		name string
		in   string
		want string
	}{
		// Newly rejected: a malformed percent escape in the path or fragment.
		// url.Parse does not escape-validate RawQuery, so the query is exempt
		// (pinned as an invariant above).
		{"literal percent in path", "/50%off", fallback},
		{"invalid escape in fragment", "/a?q=1#f%zz", fallback},

		// Newly accepted: the old guard was a blanket substring test for
		// "://" over the whole target, so it rejected these regardless of
		// where the colon-slash-slash appeared. The authorize round trip is
		// the one that matters — ":" and "/" are legal unencoded in a query,
		// so a client's redirect_uri arrives literal and the whole authorize
		// URL becomes the post-login target.
		{"unencoded :// in query", "/oauth/authorize?redirect_uri=https://c.example/cb", "/oauth/authorize?redirect_uri=https://c.example/cb"},
		// These two clear the guard, but do not read them as targets delivered
		// unchanged: http.Redirect runs path.Clean over everything before the
		// first "?", fragments included, so the wire sees "/foo:/bar" and
		// "/a#https:/evil.com". What is pinned here is the classification —
		// same origin, not the fallback. The query row above is the only one of
		// the three that also survives to the browser, which is why it is the
		// one asserted at the wire in login_test.go and the e2e scenario.
		{":// in path", "/foo://bar", "/foo://bar"},
		{":// in fragment", "/a#https://evil.com", "/a#https://evil.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SafeRedirect(tc.in, fallback); got != tc.want {
				t.Errorf("SafeRedirect(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Every ASCII control byte is rejected wherever it appears, not just at the
// index where an authority would begin.
//
// The sweep is exhaustive on purpose. A guard that enumerates a handful of
// characters at one index is only as good as the imagination of whoever wrote
// the list; `net/http` emits a path it cannot parse verbatim, and the WHATWG
// URL parser strips TAB, LF and CR before resolving, so a control byte the
// guard misses is a byte the browser resolves against a different origin.
func TestSafeRedirect_RejectsEveryControlByteAnywhere(t *testing.T) {
	const fallback = "/"
	// Bounded at 0x7f deliberately: above it, string(rune(b)) would encode two
	// UTF-8 bytes rather than the raw byte, so the loop could not construct the
	// input it claims to test. The guard operates on bytes, and every byte it
	// rejects is in this range.
	for b := 0x00; b <= 0x7f; b++ {
		if b >= 0x20 && b != 0x7f {
			continue
		}
		c := string(rune(b))
		positions := []struct {
			where string
			in    string
		}{
			{"leading position", "/" + c + "/evil.com"},
			{"interior", "/dash" + c + "board"},
			{"trailing", "/dashboard" + c},
		}
		for _, p := range positions {
			t.Run(fmt.Sprintf("0x%02x/%s", b, p.where), func(t *testing.T) {
				if got := SafeRedirect(p.in, fallback); got != fallback {
					t.Errorf("SafeRedirect(%q) = %q, want fallback %q", p.in, got, fallback)
				}
			})
		}
	}
}

// Backslash is rejected anywhere in the path, not only where it would form an
// authority. Go's url.Parse follows RFC 3986, where "\" is an ordinary path
// character; the WHATWG URL parser browsers implement treats it as "/", so
// reasoning about which index is exploitable is reasoning about which parser
// wins.
func TestSafeRedirect_RejectsBackslashInPath(t *testing.T) {
	const fallback = "/"
	for _, in := range []string{`/\evil.com`, `/a/\evil.com`, `/a\b`, `/dashboard\`, `/\\evil.com`, `/a\b?c=d`, `/\/evil.com`} {
		t.Run(in, func(t *testing.T) {
			if got := SafeRedirect(in, fallback); got != fallback {
				t.Errorf("SafeRedirect(%q) = %q, want fallback %q", in, got, fallback)
			}
		})
	}
}

// A backslash past the first "?" or "#" is left alone. By then the authority
// is settled, so it cannot move the destination — and the query is not ours to
// police: /oauth/authorize hands its whole URL to /login as the post-login
// target, so this value carries a client's query verbatim. Rejecting a
// backslash there would strand the user at the fallback after a successful
// login and silently abandon the authorization.
func TestSafeRedirect_AllowsBackslashPastPath(t *testing.T) {
	cases := []string{
		`/oauth/authorize?client_id=x&state=a\b`,
		`/dashboard?q=c:\temp`,
		`/dashboard#a\b`,
		`/dashboard?q=1#a\b`,
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if got := SafeRedirect(in, "/"); got != in {
				t.Errorf("SafeRedirect(%q) = %q, want it unchanged", in, got)
			}
		})
	}
}

// The fallback is returned verbatim, whatever it is — callers pass their own.
func TestSafeRedirect_ReturnsCallerFallback(t *testing.T) {
	if got := SafeRedirect("//evil.com", "/login"); got != "/login" {
		t.Errorf("SafeRedirect = %q, want %q", got, "/login")
	}
}

// RedirectInternal prepends the mount prefix; root/nil are byte-identical to
// http.Redirect. (fakeURLBuilder is defined in session_test.go.)
func TestRedirectInternal(t *testing.T) {
	cases := []struct {
		name    string
		urls    output.URLBuilder
		path    string
		wantLoc string
	}{
		{"nil builder (root)", nil, "/login", "/login"},
		{"root prefix", fakeURLBuilder{}, "/login", "/login"},
		{"mount prefix", fakeURLBuilder{mount: "/api/v2/auth"}, "/login?redirect=%2Fx", "/api/v2/auth/login?redirect=%2Fx"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
			RedirectInternal(rec, req, tc.urls, tc.path, http.StatusSeeOther, nil)
			if rec.Code != http.StatusSeeOther {
				t.Errorf("code = %d, want %d", rec.Code, http.StatusSeeOther)
			}
			if loc := rec.Header().Get("Location"); loc != tc.wantLoc {
				t.Errorf("Location = %q, want %q", loc, tc.wantLoc)
			}
		})
	}
}
