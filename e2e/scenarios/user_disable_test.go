//go:build e2e

package scenarios

import (
	"net/http"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

func TestUserDisable_InvalidatesTokens(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	userID := h.CreateUser("disable@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	tokens := client.FullFlow("disable@example.com", "pass123", "tools/echo", false)

	// One credential pair on both sides of the disable, so the before/after
	// pair isolates it. A fresh resource-server client per call would make the
	// "after" assertion pass on a broken binding as readily as on the disable.
	rsClientID, rsSecret := h.ResourceServerClient(rs.URI)
	if ir := h.IntrospectToken(tokens.AccessToken, rsClientID, rsSecret); !ir.Active {
		t.Fatal("expected active=true before user disable")
	}

	// Disable the user.
	h.DisableUser(userID)

	// Introspection should return inactive for disabled user.
	if ir := h.IntrospectToken(tokens.AccessToken, rsClientID, rsSecret); ir.Active {
		t.Fatal("expected active=false after user disable")
	}

	// Refresh should also fail.
	oe := h.RefreshTokenExpectError(tokens.RefreshToken, clientID)
	if oe.Error != "invalid_grant" {
		t.Errorf("expected invalid_grant error after user disable, got %q", oe.Error)
	}

	// Scenario A — session-cookie replay. A disabled user still holding a valid
	// cookie must not be able to START a fresh authorization. Without the
	// middleware check this reaches /consent and yields an authorization code.
	t.Run("SessionCookieReplayRejected", func(t *testing.T) {
		replayUserID := h.CreateUser("replay@example.com", "pass123")
		browser := h.NewClient()
		h.Login(browser, "replay@example.com", "pass123", "")
		sessionCookie := h.GetSessionCookie(browser)
		if sessionCookie == "" {
			t.Fatal("no session cookie after login")
		}

		h.DisableUser(replayUserID)

		_, challenge := client.GeneratePKCE()
		params := client.BuildAuthorizeParams("tools/echo", rs.URI, challenge, "replay-state")
		req, err := http.NewRequest(http.MethodGet,
			h.Issuer+"/oauth/authorize?"+params.Encode(), nil)
		if err != nil {
			t.Fatalf("build authorize request: %v", err)
		}
		req.AddCookie(&http.Cookie{Name: "authserver_session", Value: sessionCookie})

		// Bare client, no jar: the jar would swallow the cleared cookie before
		// the assertion below can see it.
		bare := &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := bare.Do(req)
		if err != nil {
			t.Fatalf("GET /oauth/authorize: %v", err)
		}
		defer resp.Body.Close()

		loc := resp.Header.Get("Location")
		if !strings.HasPrefix(loc, "/login") {
			t.Fatalf("Location = %q, want /login… — a disabled user's cookie must not reach consent", loc)
		}

		var cleared bool
		for _, c := range resp.Cookies() {
			if c.Name == "authserver_session" && c.Value == "" && c.MaxAge < 0 {
				cleared = true
				break
			}
		}
		if !cleared {
			t.Errorf("Set-Cookie did not clear the session cookie; got %v", resp.Cookies())
		}
	})

	// Scenario B — pre-disable code replay. A code minted while the user was
	// still active must not redeem after the disable. The middleware cannot
	// help here: POST /oauth/token is called by the client application and
	// carries no session cookie.
	t.Run("PreDisableCodeRejected", func(t *testing.T) {
		codeUserID := h.CreateUser("precode@example.com", "pass123")
		codeClient := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

		verifier, challenge := codeClient.GeneratePKCE()
		params := codeClient.BuildAuthorizeParams("tools/echo", rs.URI, challenge, "precode-state")

		result := h.Authorize(codeClient.HTTPClient, params)
		if !result.NeedsLogin {
			t.Fatalf("expected login redirect, got %+v", result)
		}
		h.Login(codeClient.HTTPClient, "precode@example.com", "pass123", "")

		result = h.Authorize(codeClient.HTTPClient, params)
		if !result.NeedsConsent {
			t.Fatalf("expected consent redirect, got %+v", result)
		}
		code := h.GrantConsent(codeClient.HTTPClient, result.SessionID, []string{"tools/echo"}, false)
		if code == "" {
			t.Fatal("no authorization code after consent")
		}

		// Disable AFTER the code exists: it was minted while the user was
		// active, so only the exchange can catch this.
		h.DisableUser(codeUserID)

		oe := h.ExchangeCodeExpectError(code, verifier, clientID, redirectURI)
		if oe.Error != "invalid_grant" {
			t.Errorf("exchanging a pre-disable code: got %q, want invalid_grant", oe.Error)
		}
	})
}
