//go:build e2e

package scenarios

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// Topology: oidc-federated-login (docs/topologies/oidc-federated-login.md).
//
// The harness wires the production OIDC adapter and facade against an
// in-process OpenID Provider (e2e.MockOIDCProvider): /oidc/start redirects to
// its authorize endpoint, which bounces straight back to /oidc/callback with a
// code; the AS redeems it at the provider's token endpoint and verifies the
// returned ID token with the real verifier. So the ID-token checks (iss, aud,
// exp, nonce, signature, sub) and the user reconciliation logic run for real;
// only the human at the IdP is simulated.
//
// The page promises: users are looked up by (provider, sub) and provisioned
// on first login; a disabled user is refused; user.oidc_login /
// user.oidc_login_failed audit rows; the session resumes the original
// /authorize and from there the flow is single-mcp.

type oidcFixture struct {
	h     *e2e.TestHarness
	op    *e2e.MockOIDCProvider
	agent string
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	op := e2e.NewMockOIDCProvider(t, "authserver-at-okta", "okta-client-secret")
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{EnableAdminAPI: true, OIDC: op}, []string{"tools/echo"})
	f := &oidcFixture{h: h, op: op}
	f.agent = h.AdminCreatePublicClient("my-agent", []string{"authorization_code"}, "tools/echo", []string{topoRedirect})
	return f
}

// federatedLogin runs /oidc/start → IdP → /oidc/callback on c and returns the
// callback's status and Location.
func (f *oidcFixture) federatedLogin(t *testing.T, c *http.Client, redirect string) (int, string) {
	t.Helper()
	start, err := c.Get(f.h.Issuer + "/oidc/start?redirect=" + url.QueryEscape(redirect))
	if err != nil {
		t.Fatalf("GET /oidc/start: %v", err)
	}
	start.Body.Close()
	if start.StatusCode != http.StatusFound && start.StatusCode != http.StatusSeeOther {
		t.Fatalf("/oidc/start: status %d", start.StatusCode)
	}
	idp, err := c.Get(start.Header.Get("Location"))
	if err != nil {
		t.Fatalf("GET IdP authorize: %v", err)
	}
	idp.Body.Close()
	cb := idp.Header.Get("Location")
	if cb == "" {
		t.Fatalf("IdP authorize: no redirect (status %d)", idp.StatusCode)
	}
	return f.callback(t, c, cb)
}

func (f *oidcFixture) callback(t *testing.T, c *http.Client, cb string) (int, string) {
	t.Helper()
	resp, err := c.Get(cb)
	if err != nil {
		t.Fatalf("GET /oidc/callback: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location")
}

// authorizeParams is the agent's authorization request at mcp-0.
func (f *oidcFixture) authorizeParams() (url.Values, string) {
	v, ch := topoPKCE()
	return topoAuthorizeParams(f.agent, topoRedirect, "mcp-0", "tools/echo", ch, "S256"), v
}

// sessionUser reports whether c holds a session and, if it does, completes
// the agent flow and returns the token's sub.
func (f *oidcFixture) sessionUser(t *testing.T, c *http.Client) (string, bool) {
	t.Helper()
	params, v := f.authorizeParams()
	res := f.h.Authorize(c, params)
	if res.NeedsLogin {
		return "", false
	}
	code := res.Code
	if res.NeedsConsent {
		code = f.h.GrantConsent(c, res.SessionID, []string{"tools/echo"}, false)
	}
	tok := topoRedeem(t, f.h, code, v, f.agent)
	if !tok.OK() {
		t.Fatalf("redeem after federated login: %s", tok.Raw)
	}
	return stringClaim(parseJWTClaims(t, tok.AccessToken()), "sub"), true
}

type oidcUserView struct {
	ID, Email, Status, Provider string
}

func (f *oidcFixture) users(t *testing.T) []oidcUserView {
	t.Helper()
	resp := f.h.AdminRequest(http.MethodGet, "/admin/users?limit=200", nil)
	defer resp.Body.Close()
	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("decode users: %v", err)
	}
	var list []map[string]any
	if json.Unmarshal(raw, &list) != nil {
		var wrapped struct {
			Users []map[string]any `json:"users"`
		}
		_ = json.Unmarshal(raw, &wrapped)
		list = wrapped.Users
	}
	out := make([]oidcUserView, 0, len(list))
	for _, u := range list {
		s := func(k string) string { v, _ := u[k].(string); return v }
		out = append(out, oidcUserView{ID: s("id"), Email: s("email"), Status: s("status"), Provider: s("provider")})
	}
	return out
}

func TestTopologyOIDCFederatedLogin_Adversarial(t *testing.T) {
	t.Parallel()
	t.Run("LegitimateFlow_ProvisionResumeAndAudit", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t)
		f.op.SetNextIdentity(e2e.OIDCIdentity{Subject: "okta-00u1", Email: "alice@corp.example", Name: "Alice"})
		c := f.h.NewClient()
		params, _ := f.authorizeParams()
		first := f.h.Authorize(c, params)
		if !first.NeedsLogin {
			t.Fatalf("expected a login redirect, got %+v", first)
		}
		resume := extractRedirectParam(first.Location)
		st, loc := f.federatedLogin(t, c, resume)
		if st != http.StatusSeeOther || !strings.HasSuffix(loc, resume) {
			t.Fatalf("callback: status %d Location %q, want 303 back to %q", st, loc, resume)
		}
		sub, ok := f.sessionUser(t, c)
		if !ok {
			t.Fatal("no session after a successful federated login")
		}
		var alice *oidcUserView
		for _, u := range f.users(t) {
			if u.Email == "alice@corp.example" {
				u := u
				alice = &u
			}
		}
		if alice == nil || alice.ID != sub || alice.Provider != "oidc" {
			t.Errorf("provisioned user = %+v, token sub = %q; want one oidc user whose id is the sub", alice, sub)
		}
		// A second login with the same upstream sub is the same local user.
		f.op.SetNextIdentity(e2e.OIDCIdentity{Subject: "okta-00u1", Email: "alice@corp.example"})
		c2 := f.h.NewClient()
		f.federatedLogin(t, c2, "/")
		if sub2, _ := f.sessionUser(t, c2); sub2 != sub {
			t.Errorf("second login resolved to %q, want the same user %q", sub2, sub)
		}
		topoExpectAudit(t, f.h, "user.oidc_login", "for the provisioned user", func(r topoAuditRow) bool {
			return r.ActorID == sub
		})
	})

	t.Run("IDTokenVerification_TamperedTokensRefused", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t)
		for name, tamper := range map[string]e2e.OIDCTamper{
			"wrong-issuer":   {Issuer: "https://evil-idp.example"},
			"wrong-audience": {Audience: "some-other-client"},
			"nonce-mismatch": {Nonce: "not-the-nonce-we-sent"},
			"expired":        {Expired: true},
			"foreign-key":    {RogueKey: true},
			"no-subject":     {OmitSubject: true},
		} {
			t.Run(name, func(t *testing.T) {
				f.op.SetNextIdentity(e2e.OIDCIdentity{Subject: "okta-" + name, Email: name + "@corp.example"})
				f.op.SetNextTamper(tamper)
				c := f.h.NewClient()
				st, loc := f.federatedLogin(t, c, "/")
				if st != http.StatusUnauthorized {
					t.Errorf("callback status %d (Location %q), want 401", st, loc)
				}
				if _, ok := f.sessionUser(t, c); ok {
					t.Error("session established from a tampered ID token")
				}
			})
		}
		for _, u := range f.users(t) {
			if strings.HasSuffix(u.Email, "@corp.example") {
				t.Errorf("a tampered login provisioned user %+v", u)
			}
		}
		topoExpectAudit(t, f.h, "user.oidc_login_failed", "code exchange failed", func(r topoAuditRow) bool {
			return strings.Contains(r.Detail, "code exchange failed")
		})
	})

	t.Run("StateBinding_ReplayForeignBrowserAndForgery", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t)
		f.op.SetNextIdentity(e2e.OIDCIdentity{Subject: "okta-state", Email: "state@corp.example"})
		victim := f.h.NewClient()
		start, _ := victim.Get(f.h.Issuer + "/oidc/start?redirect=%2F")
		start.Body.Close()
		idp, _ := victim.Get(start.Header.Get("Location"))
		idp.Body.Close()
		cb := idp.Header.Get("Location")

		// Login CSRF: the callback URL delivered to a different browser.
		attacker := f.h.NewClient()
		if st, _ := f.callback(t, attacker, cb); st != http.StatusBadRequest {
			t.Errorf("callback in a browser without the state cookie: status %d, want 400", st)
		}
		if _, ok := f.sessionUser(t, attacker); ok {
			t.Error("callback established a session in a foreign browser")
		}
		// Forged state.
		u, _ := url.Parse(cb)
		q := u.Query()
		q.Set("state", q.Get("state")+"x")
		u.RawQuery = q.Encode()
		if st, _ := f.callback(t, victim, u.String()); st != http.StatusBadRequest {
			t.Errorf("tampered state: status %d, want 400", st)
		}
		// Replay after a successful use.
		f.op.SetNextIdentity(e2e.OIDCIdentity{Subject: "okta-state", Email: "state@corp.example"})
		c := f.h.NewClient()
		s2, _ := c.Get(f.h.Issuer + "/oidc/start?redirect=%2F")
		s2.Body.Close()
		i2, _ := c.Get(s2.Header.Get("Location"))
		i2.Body.Close()
		cb2 := i2.Header.Get("Location")
		if st, _ := f.callback(t, c, cb2); st != http.StatusSeeOther {
			t.Fatalf("first callback: %d", st)
		}
		fresh := f.h.NewClient()
		fresh.Jar = c.Jar
		if st, _ := f.callback(t, fresh, cb2); st == http.StatusSeeOther {
			t.Error("replayed callback (same code + state) succeeded")
		}
	})

	t.Run("OpenRedirect_AfterLoginStaysOnAS", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t)
		for _, target := range []string{"https://evil.example/steal", "//evil.example/steal", "/\\evil.example"} {
			f.op.SetNextIdentity(e2e.OIDCIdentity{Subject: "okta-redir", Email: "redir@corp.example"})
			st, loc := f.federatedLogin(t, f.h.NewClient(), target)
			if strings.Contains(loc, "evil.example") {
				t.Errorf("redirect=%q: post-login Location %q (status %d) leaves the AS", target, loc, st)
			}
		}
	})

	t.Run("DisabledFederatedUser_Refused", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t)
		f.op.SetNextIdentity(e2e.OIDCIdentity{Subject: "okta-dis", Email: "dis@corp.example"})
		c := f.h.NewClient()
		f.federatedLogin(t, c, "/")
		sub, ok := f.sessionUser(t, c)
		if !ok {
			t.Fatal("precondition: first login")
		}
		f.h.DisableUser(sub)
		f.op.SetNextIdentity(e2e.OIDCIdentity{Subject: "okta-dis", Email: "dis@corp.example"})
		c2 := f.h.NewClient()
		if st, _ := f.federatedLogin(t, c2, "/"); st != http.StatusUnauthorized {
			t.Errorf("disabled user: callback %d, want 401", st)
		}
		if _, ok := f.sessionUser(t, c2); ok {
			t.Error("disabled federated user got a session")
		}
		topoExpectAudit(t, f.h, "user.oidc_login_failed", "user disabled", func(r topoAuditRow) bool {
			return r.ActorID == sub && strings.Contains(r.Detail, "user disabled")
		})
	})

	// Federated identity is keyed on (provider, sub) — the page says so and
	// the code does no email linking. A federated login whose email equals a
	// local account's must therefore neither become that local account nor
	// fail as a server error.
	t.Run("EmailCollisionWithLocalAccount_NoTakeoverNoServerError", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t)
		local := f.h.CreateUser("boss@corp.example", topoPassword)
		f.op.SetNextIdentity(e2e.OIDCIdentity{Subject: "okta-impostor", Email: "boss@corp.example"})
		c := f.h.NewClient()
		st, _ := f.federatedLogin(t, c, "/")
		t.Logf("federated login colliding with a local account's email: callback status %d", st)
		if st >= 500 {
			t.Errorf("%s: a federated login whose email matches an existing local account answers %d (server error) instead of a handled refusal or a separate account; that address can never sign in through the IdP",
				topoFindingPrefix, st)
		}
		if sub, ok := f.sessionUser(t, c); ok && sub == local {
			t.Errorf("federated login took over the local account %s by email", local)
		}
		topoExpectAudit(t, f.h, "user.oidc_login_failed", "reason=email_in_use", func(r topoAuditRow) bool {
			return topoDetailHas(r.Detail, "reason=email_in_use", "provider_sub=okta-impostor")
		})
	})

	// IdPs do not always release an email (no email scope consent, service
	// principals, Entra guests). The page lists email as a mapped claim, and
	// the provider port documents it as "may be empty".
	t.Run("UsersWithoutEmailClaim_AllCanSignIn", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t)
		subs := map[string]bool{}
		signedIn := 0
		for _, upstream := range []string{"okta-noemail-1", "okta-noemail-2"} {
			f.op.SetNextIdentity(e2e.OIDCIdentity{Subject: upstream})
			c := f.h.NewClient()
			st, _ := f.federatedLogin(t, c, "/")
			sub, ok := f.sessionUser(t, c)
			if !ok {
				t.Errorf("%s: federated user %q with no email claim cannot sign in (callback status %d); only the first email-less user ever provisions",
					topoFindingPrefix, upstream, st)
				continue
			}
			subs[sub] = true
			signedIn++
		}
		if signedIn == 2 && len(subs) == 1 {
			t.Error("two distinct upstream subjects resolved to one local user")
		}

		// A returning email-less user is found by (provider, sub), not
		// provisioned again.
		f.op.SetNextIdentity(e2e.OIDCIdentity{Subject: "okta-noemail-1"})
		c := f.h.NewClient()
		f.federatedLogin(t, c, "/")
		if sub, ok := f.sessionUser(t, c); !ok {
			t.Error("returning email-less federated user cannot sign in")
		} else if !subs[sub] {
			t.Errorf("returning email-less federated user resolved to a new local user %s", sub)
		}
	})

	t.Run("FederatedAccount_NoLocalPasswordLogin", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t)
		f.op.SetNextIdentity(e2e.OIDCIdentity{Subject: "okta-pw", Email: "pw@corp.example"})
		f.federatedLogin(t, f.h.NewClient(), "/")
		c := f.h.NewClient()
		for _, pw := range []string{"", topoPassword, "password"} {
			resp, err := f.h.LoginResponse(c, "pw@corp.example", pw, "")
			if err == nil {
				resp.Body.Close()
			}
		}
		if _, ok := f.sessionUser(t, c); ok {
			t.Error("password login succeeded for a federated-only account")
		}
		topoExpectAudit(t, f.h, "user.login_failed", "reason=user_not_local", func(r topoAuditRow) bool {
			return strings.Contains(r.Detail, "reason=user_not_local")
		})
	})
}
