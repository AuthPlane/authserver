//go:build integration

package public_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain/session"
	"github.com/authplane/authserver/internal/domain/user"
)

// Matrix: 12.2 — upgraded from ⚠️: consent screen shows requested scopes
// Matrix: 12.3 — upgraded from ⚠️: consent screen shows client name
func TestConsentScreen_ShowsScopesAndClientName(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)
	ctx := context.Background()
	now := time.Now().UTC()

	// Create user and log in.
	_, err := env.authSvc.CreateUser(ctx, "consent-screen@example.com", "", "pass123", user.RoleUser)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	u, err := env.authSvc.Authenticate(ctx, "consent-screen@example.com", "pass123")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	// Create auth session (the authorize endpoint would normally do this).
	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)
	sess := &session.AuthSession{
		ID:                  crypto.GenerateRandomString(16),
		ClientID:            c.ID,
		UserID:              u.ID,
		RedirectURI:         "https://app.example.com/callback",
		Scope:               "tools/query",
		Resource:            "https://mcp.example.com",
		State:               "s1",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(session.AuthCodeTTL),
		CreatedAt:           now,
	}
	if err := env.stores.Stores.Session.Create(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Log in to get cookies.
	jar := &testCookieJar{}
	hc := &http.Client{Jar: jar, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	loginResp, err := postLogin(t, hc, env.ts.URL, "consent-screen@example.com", "pass123")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginResp.Body.Close()

	// GET /consent with session_id.
	consentResp, err := hc.Get(env.ts.URL + "/consent?session_id=" + sess.ID)
	if err != nil {
		t.Fatalf("get consent: %v", err)
	}
	defer consentResp.Body.Close()

	if consentResp.StatusCode != http.StatusOK {
		t.Fatalf("consent status: got %d, want 200", consentResp.StatusCode)
	}

	body, _ := io.ReadAll(consentResp.Body)
	bodyStr := string(body)

	// 12.3: Client name must appear in the consent page.
	if !strings.Contains(bodyStr, c.Name) {
		t.Errorf("consent page should contain client name %q", c.Name)
	}

	// 12.2: Requested scope must appear in the consent page.
	if !strings.Contains(bodyStr, "tools/query") {
		t.Error("consent page should contain requested scope 'tools/query'")
	}
}

// Matrix: 12.9 — upgraded from ⚠️: CSRF protection on consent form
func TestConsentScreen_CSRFProtection(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)
	ctx := context.Background()
	now := time.Now().UTC()

	// Create user and log in.
	_, err := env.authSvc.CreateUser(ctx, "csrf-test@example.com", "", "pass123", user.RoleUser)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	u, err := env.authSvc.Authenticate(ctx, "csrf-test@example.com", "pass123")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	// Create auth session.
	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)
	sess := &session.AuthSession{
		ID:                  crypto.GenerateRandomString(16),
		ClientID:            c.ID,
		UserID:              u.ID,
		RedirectURI:         "https://app.example.com/callback",
		Scope:               "tools/query",
		Resource:            "https://mcp.example.com",
		State:               "s1",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(session.AuthCodeTTL),
		CreatedAt:           now,
	}
	if err := env.stores.Stores.Session.Create(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Log in to get cookies.
	jar := &testCookieJar{}
	hc := &http.Client{Jar: jar, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	loginResp, err := postLogin(t, hc, env.ts.URL, "csrf-test@example.com", "pass123")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginResp.Body.Close()

	// POST /consent without CSRF token → should be rejected with 403.
	consentForm := url.Values{
		"session_id": {sess.ID},
		"action":     {"allow"},
		"scopes":     {"tools/query"},
		// csrf_token intentionally omitted
	}
	consentResp, err := hc.PostForm(env.ts.URL+"/consent", consentForm)
	if err != nil {
		t.Fatalf("post consent: %v", err)
	}
	defer consentResp.Body.Close()

	if consentResp.StatusCode != http.StatusForbidden {
		t.Errorf("consent without CSRF: got %d, want 403", consentResp.StatusCode)
	}
}

// Matrix: 12.10 — consent endpoint must reject non-POST methods (PUT, DELETE, PATCH → 405)
func TestConsentEndpoint_UnsupportedMethods_Return405(t *testing.T) {
	env := newOAuthTestServer(t)

	methods := []string{"PUT", "DELETE", "PATCH"}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req, err := http.NewRequest(method, env.ts.URL+"/consent", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("%s /consent: got %d, want 405", method, resp.StatusCode)
			}
		})
	}
}
