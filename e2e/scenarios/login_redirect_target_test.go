//go:build e2e

package scenarios

import (
	"testing"

	"github.com/authplane/authserver/e2e"
)

// TestLogin_RedirectTarget_StaysOnThisOrigin drives a real login against the
// running server and asserts the Location header it emits.
//
// The post-login redirect target comes from the request (query or form), and
// the redirect is issued with a session cookie already set. This exercises the
// full binary — router, handlers, and net/http's header writer — so it catches
// a target that survives validation but is reshaped somewhere downstream, in
// the one place that reflects what a browser would actually receive.
func TestLogin_RedirectTarget_StaysOnThisOrigin(t *testing.T) {
	// No resourceScopes: this scenario never reaches authorize, token or a
	// resource, so an MCP resource server would only add a way for it to fail
	// for reasons unrelated to the redirect target it asserts on.
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{})

	const email, password = "redirect-target@example.com", "pass123"
	h.CreateUser(email, password)

	cases := []struct {
		name     string
		redirect string
		want     string
	}{
		// Percent-encoded on the wire as %2F%09%2Fevil.com. The leading "/"
		// matters: without it the target is rejected for not being rooted, and
		// the case would pass against an unfixed server without proving
		// anything.
		{"tab before authority", "/\t/evil.com", "/"},
		{"newline before authority", "/\n/evil.com", "/"},
		{"scheme-relative", "//evil.com", "/"},
		{"three leading slashes", "///evil.com", "/"},
		{"backslash authority", `/\evil.com`, "/"},
		{"absolute", "https://evil.com", "/"},
		{"legitimate path still honoured", "/dashboard", "/dashboard"},
		// /oauth/authorize hands its entire URL to /login as the post-login
		// target, so this value carries a client's query verbatim. A backslash
		// there is the client's business — rejecting it would resume nothing
		// and drop the user at "/" after a successful login.
		{"client query survives the authorize round trip", `/oauth/authorize?client_id=x&state=a\b`, `/oauth/authorize?client_id=x&state=a\b`},
		// A client's unencoded redirect_uri used to send the whole post-login
		// target to the fallback, abandoning the authorization. Asserted here
		// too: this is the one reclassification a user would notice.
		{"unencoded :// in query reaches the wire intact", "/oauth/authorize?redirect_uri=https://c.example/cb", "/oauth/authorize?redirect_uri=https://c.example/cb"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := h.NewClient()
			resp, err := h.LoginResponse(client, email, password, tc.redirect)
			if err != nil {
				// net/http parses Location before consulting CheckRedirect, so
				// a value it cannot parse arrives here rather than as a header
				// to assert on. That is still a failure of this test's claim:
				// the server emitted something that is not the destination.
				t.Fatalf("POST /login with redirect=%q: %v", tc.redirect, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != 303 {
				t.Fatalf("POST /login: expected 303, got %d", resp.StatusCode)
			}
			// Assert the expected destination rather than the absence of the
			// payload: equality cannot be satisfied by a mangled or partially
			// stripped variant of the supplied value.
			if loc := resp.Header.Get("Location"); loc != tc.want {
				t.Errorf("Location = %q, want %q", loc, tc.want)
			}
		})
	}
}
