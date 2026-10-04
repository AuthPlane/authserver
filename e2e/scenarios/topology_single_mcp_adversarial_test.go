//go:build e2e

package scenarios

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// Topology: single-mcp (docs/topologies/single-mcp.md).
//
// One Mint Resource (mcp-0, scopes tools/echo + tools/db_query), one public
// agent registered as the page prescribes (grant_types=[authorization_code],
// token_endpoint_auth_method=none, scope = the catalog), one user. The page
// promises: PKCE for every client, a consent_grants row per (user, agent,
// resource), a JWT with aud = resource URI, client_id = agent, sub = user,
// scope = what was consented, and consent.granted + token.issued audit rows.
//
// Each subtest probes the flow the way a default-configured or hostile client
// would: omitting optional parameters, replaying codes and refresh tokens,
// presenting another client's code, asking for more than was consented.

type singleMCPFixture struct {
	h        *e2e.TestHarness
	rs       *e2e.MCPResourceServer
	agent    string
	userID   string
	email    string
	rsID     string
	rsSecret string
	otherURI string
}

const singleMCPSlug = "mcp-0"

func newSingleMCPFixture(t *testing.T) *singleMCPFixture {
	t.Helper()
	return newSingleMCPFixtureWithGrants(t, []string{"authorization_code"})
}

// newSingleMCPRefreshFixture is the page's fixture with the agent also
// registered for refresh_token. The AS issues and honors refresh tokens only
// for clients registered for that grant, so every subtest that exercises a
// refresh token needs this agent; the page's own agent gets none.
func newSingleMCPRefreshFixture(t *testing.T) *singleMCPFixture {
	t.Helper()
	return newSingleMCPFixtureWithGrants(t, []string{"authorization_code", "refresh_token"})
}

func newSingleMCPFixtureWithGrants(t *testing.T, agentGrants []string) *singleMCPFixture {
	t.Helper()
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{EnableAdminAPI: true},
		[]string{"tools/echo", "tools/db_query"})
	f := &singleMCPFixture{h: h, rs: servers[0], email: "single-alice@example.com"}
	f.userID = h.CreateUser(f.email, topoPassword)
	// The agent as the page registers it (public, authorization_code only,
	// scope = the resource catalog), plus refresh_token when the subtest needs
	// refresh tokens.
	f.agent = h.AdminCreatePublicClient("my-agent", agentGrants,
		"tools/echo tools/db_query", []string{topoRedirect})
	// A second, unrelated resource the agent was never pointed at.
	f.otherURI = "https://mcp-other.single.test"
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug: "mcp-other", URI: f.otherURI, BackendKind: "mint", DisplayName: "other",
		Scopes: []e2e.AdminScope{{Name: "tools/echo"}},
	})
	f.rsID, f.rsSecret = topoRSCreds(t, h, singleMCPSlug)
	return f
}

func (f *singleMCPFixture) refresh(t *testing.T, rt, scope, resource string) topoResp {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}
	if scope != "" {
		form.Set("scope", scope)
	}
	if resource != "" {
		form.Set("resource", resource)
	}
	return topoToken(t, f.h, form, topoAuthNone, f.agent, "")
}

func (f *singleMCPFixture) active(t *testing.T, tok string) bool {
	t.Helper()
	return f.h.IntrospectToken(tok, f.rsID, f.rsSecret).Active
}

func TestTopologySingleMCP_Adversarial(t *testing.T) {
	t.Parallel()
	t.Run("LegitimateFlow_DocumentedTokenShapeAndAudit", func(t *testing.T) {
		t.Parallel()
		f := newSingleMCPFixture(t)
		tok := topoUserToken(t, f.h, f.email, f.agent, singleMCPSlug, []string{"tools/echo", "tools/db_query"})
		c := parseJWTClaims(t, tok.AccessToken())
		if aud := topoAud(c); len(aud) != 1 || aud[0] != f.rs.URI {
			t.Errorf("aud = %v, want [%s]", aud, f.rs.URI)
		}
		if got := stringClaim(c, "client_id"); got != f.agent {
			t.Errorf("client_id = %q, want agent %q", got, f.agent)
		}
		if got := stringClaim(c, "sub"); got != f.userID {
			t.Errorf("sub = %q, want user %q", got, f.userID)
		}
		if got := strings.Join(topoScopes(stringClaim(c, "scope")), " "); got != "tools/db_query tools/echo" {
			t.Errorf("scope = %q, want both consented scopes", got)
		}
		mc := e2e.NewMCPClient(t, f.h, f.rs, f.agent, topoRedirect)
		if st, _ := mc.CallTool("/tools/echo", tok.AccessToken(), `"hi"`); st != http.StatusOK {
			t.Errorf("RS call: status %d, want 200", st)
		}
		topoExpectAudit(t, f.h, "consent.granted", "for (user, agent, mcp-0)", func(r topoAuditRow) bool {
			return r.ActorID == f.userID && r.ClientID == f.agent && strings.Contains(r.Detail, "resource="+singleMCPSlug)
		})
		topoExpectAudit(t, f.h, "token.issued", "for (user, agent)", func(r topoAuditRow) bool {
			return r.ActorID == f.userID && r.ClientID == f.agent && strings.Contains(r.Detail, "family=")
		})
	})

	t.Run("OmittedScope_DefaultsToCatalogWithinCeiling", func(t *testing.T) {
		t.Parallel()
		f := newSingleMCPFixture(t)
		// A second agent whose ceiling holds only tools/echo: the default the
		// AS proposes for an omitted scope must be narrowed to it.
		narrow := f.h.AdminCreatePublicClient("narrow-agent", []string{"authorization_code"}, "tools/echo", []string{topoRedirect})
		for _, tc := range []struct {
			name, client string
			allowed      []string
		}{
			{"catalog-ceiling", f.agent, []string{"tools/echo", "tools/db_query"}},
			{"narrow-ceiling", narrow, []string{"tools/echo"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c := topoLoggedIn(t, f.h, f.email)
				v, ch := topoPKCE()
				res := f.h.Authorize(c, topoAuthorizeParams(tc.client, topoRedirect, singleMCPSlug, "", ch, "S256"))
				if !res.NeedsConsent {
					t.Fatalf("expected consent for an omitted scope, got %+v", res)
				}
				offered := topoConsentOffered(t, f.h, c, res.SessionID)
				topoAssertScopeWithin(t, "consent screen default", strings.Join(offered, " "), true, tc.allowed...)
				code := f.h.GrantConsent(c, res.SessionID, offered, false)
				tok := topoRedeem(t, f.h, code, v, tc.client)
				if !tok.OK() {
					t.Fatalf("redeem: %d %s", tok.Status, tok.Raw)
				}
				topoAssertScopeWithin(t, "issued token", stringClaim(parseJWTClaims(t, tok.AccessToken()), "scope"), true, tc.allowed...)
			})
		}
	})

	t.Run("OmittedResource_TokenNotAudiencedToMCP", func(t *testing.T) {
		t.Parallel()
		f := newSingleMCPFixture(t)
		c := topoLoggedIn(t, f.h, f.email)
		v, ch := topoPKCE()
		code := topoCodeFor(t, f.h, c, topoAuthorizeParams(f.agent, topoRedirect, "", "tools/echo", ch, "S256"), []string{"tools/echo"})
		tok := topoRedeem(t, f.h, code, v, f.agent)
		if !tok.OK() {
			t.Fatalf("redeem: %d %s", tok.Status, tok.Raw)
		}
		for _, a := range topoAud(parseJWTClaims(t, tok.AccessToken())) {
			if a == f.rs.URI || a == f.otherURI {
				t.Errorf("a resource-less grant produced a token audienced to %q", a)
			}
		}
		mc := e2e.NewMCPClient(t, f.h, f.rs, f.agent, topoRedirect)
		if st, _ := mc.CallTool("/tools/echo", tok.AccessToken(), `"x"`); st != http.StatusUnauthorized {
			t.Errorf("RS accepted a resource-less token: status %d, want 401", st)
		}

		// Naming the resource only at the token endpoint must not bind the
		// token to it (RFC 8707 §2.2).
		v2, ch2 := topoPKCE()
		code2 := topoCodeFor(t, f.h, c, topoAuthorizeParams(f.agent, topoRedirect, "", "tools/echo", ch2, "S256"), []string{"tools/echo"})
		late := topoToken(t, f.h, url.Values{
			"grant_type": {"authorization_code"}, "code": {code2}, "redirect_uri": {topoRedirect},
			"code_verifier": {v2}, "resource": {f.rs.URI},
		}, topoAuthNone, f.agent, "")
		if late.OK() || late.Err() != "invalid_target" {
			t.Errorf("resource named only at /token: status %d error %q, want invalid_target", late.Status, late.Err())
		}
	})

	t.Run("PKCE_OmittedOrDowngradedIsRefused", func(t *testing.T) {
		t.Parallel()
		f := newSingleMCPFixture(t)
		c := topoLoggedIn(t, f.h, f.email)
		_, ch := topoPKCE()
		for name, p := range map[string]url.Values{
			"no-code_challenge":        topoAuthorizeParams(f.agent, topoRedirect, singleMCPSlug, "tools/echo", "", ""),
			"no-code_challenge_method": topoAuthorizeParams(f.agent, topoRedirect, singleMCPSlug, "tools/echo", ch, ""),
			"method-plain":             topoAuthorizeParams(f.agent, topoRedirect, singleMCPSlug, "tools/echo", ch, "plain"),
		} {
			st, loc := topoAuthorizeRaw(t, f.h, c, p)
			if strings.Contains(loc, "code=") || strings.HasPrefix(loc, "/consent") {
				t.Errorf("%s: authorization proceeded (status %d, Location %q); PKCE S256 is mandatory", name, st, loc)
			}
		}
		// A correct challenge with the wrong verifier at /token.
		code, _, _ := f.h.RunFlowC1Consent(f.email, topoPassword, f.agent, topoRedirect, singleMCPSlug,
			[]string{"tools/echo"}, []string{"tools/echo"})
		wrong, _ := topoPKCE()
		r := topoRedeem(t, f.h, code, wrong, f.agent)
		if r.OK() || r.Err() != "invalid_grant" {
			t.Errorf("wrong code_verifier: status %d error %q, want invalid_grant", r.Status, r.Err())
		}
		topoExpectAudit(t, f.h, "token.issue_denied", "with reason=invalid_grant", func(row topoAuditRow) bool {
			return row.ClientID == f.agent && strings.Contains(row.Detail, "reason=invalid_grant")
		})
	})

	t.Run("RedirectURI_OmittedOrForeignIsRefused", func(t *testing.T) {
		t.Parallel()
		f := newSingleMCPFixture(t)
		c := topoLoggedIn(t, f.h, f.email)
		_, ch := topoPKCE()
		for name, redirect := range map[string]string{"omitted": "", "unregistered": "https://evil.example/cb"} {
			st, loc := topoAuthorizeRaw(t, f.h, c, topoAuthorizeParams(f.agent, redirect, singleMCPSlug, "tools/echo", ch, "S256"))
			if strings.Contains(loc, "evil.example") || strings.Contains(loc, "code=") || strings.HasPrefix(loc, "/consent") {
				t.Errorf("redirect_uri %s: status %d Location %q — must neither redirect off-registry nor proceed", name, st, loc)
			}
		}
		// redirect_uri omitted at /token for a code that was bound to one.
		code, v, _ := f.h.RunFlowC1Consent(f.email, topoPassword, f.agent, topoRedirect, singleMCPSlug,
			[]string{"tools/echo"}, []string{"tools/echo"})
		r := topoToken(t, f.h, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {v}},
			topoAuthNone, f.agent, "")
		if r.OK() || r.Err() != "invalid_grant" {
			t.Errorf("redirect_uri omitted at /token: status %d error %q, want invalid_grant", r.Status, r.Err())
		}
	})

	t.Run("UnderPrivilegedConsent_CannotWiden", func(t *testing.T) {
		t.Parallel()
		f := newSingleMCPRefreshFixture(t)
		// The user ticks only tools/echo of the two requested scopes.
		code, v, _ := f.h.RunFlowC1Consent(f.email, topoPassword, f.agent, topoRedirect, singleMCPSlug,
			[]string{"tools/echo", "tools/db_query"}, []string{"tools/echo"})
		tok := topoRedeem(t, f.h, code, v, f.agent)
		if !tok.OK() {
			t.Fatalf("redeem: %d %s", tok.Status, tok.Raw)
		}
		topoAssertScopeWithin(t, "narrowed consent", tok.Scope(), true, "tools/echo")
		mc := e2e.NewMCPClient(t, f.h, f.rs, f.agent, topoRedirect)
		if st, _ := mc.CallTool("/tools/db_query", tok.AccessToken(), "{}"); st != http.StatusForbidden {
			t.Errorf("unconsented tool: status %d, want 403", st)
		}
		if tok.Refresh() == "" {
			t.Fatal("no refresh token issued to an agent registered for refresh_token")
		}
		wide := f.refresh(t, tok.Refresh(), "tools/echo tools/db_query", "")
		if wide.OK() || wide.Err() != "invalid_scope" {
			t.Errorf("refresh widening: status %d error %q, want invalid_scope", wide.Status, wide.Err())
		}
		same := f.refresh(t, tok.Refresh(), "", "")
		if !same.OK() {
			t.Fatalf("refresh with omitted scope: %d %s", same.Status, same.Raw)
		}
		topoAssertScopeWithin(t, "refresh, scope omitted", same.Scope(), true, "tools/echo")
	})

	t.Run("RefreshCannotRetargetResource", func(t *testing.T) {
		t.Parallel()
		f := newSingleMCPRefreshFixture(t)
		tok := topoUserToken(t, f.h, f.email, f.agent, singleMCPSlug, []string{"tools/echo"})
		if tok.Refresh() == "" {
			t.Fatal("no refresh token issued to an agent registered for refresh_token")
		}
		r := f.refresh(t, tok.Refresh(), "", f.otherURI)
		if r.OK() || r.Err() != "invalid_target" {
			t.Errorf("refresh with resource=%s: status %d error %q, want invalid_target", f.otherURI, r.Status, r.Err())
		}
	})

	t.Run("ForeignClient_RefusedAndCannotWiden", func(t *testing.T) {
		t.Parallel()
		f := newSingleMCPFixture(t)
		foreign := f.h.AdminCreatePublicClient("foreign-agent", []string{"authorization_code"}, "tools/echo", []string{topoRedirect})
		c := topoLoggedIn(t, f.h, f.email)
		_, ch := topoPKCE()
		res := f.h.Authorize(c, topoAuthorizeParams(foreign, topoRedirect, singleMCPSlug, "tools/db_query", ch, "S256"))
		if res.Error != "invalid_scope" {
			t.Errorf("foreign client asking beyond its ceiling: %+v, want error=invalid_scope", res)
		}
		// The foreign client redeems a code issued to the agent.
		code, v, _ := f.h.RunFlowC1Consent(f.email, topoPassword, f.agent, topoRedirect, singleMCPSlug,
			[]string{"tools/echo"}, []string{"tools/echo"})
		r := topoRedeem(t, f.h, code, v, foreign)
		if r.OK() || r.Err() != "invalid_client" {
			t.Errorf("foreign client redeeming the agent's code: status %d error %q, want invalid_client", r.Status, r.Err())
		}
		// The user's consent to the agent is not consent to anyone else: a
		// second user authorizing the agent sees a consent screen.
		const bob = "single-bob@example.com"
		f.h.CreateUser(bob, topoPassword)
		bc := topoLoggedIn(t, f.h, bob)
		_, ch2 := topoPKCE()
		if br := f.h.Authorize(bc, topoAuthorizeParams(f.agent, topoRedirect, singleMCPSlug, "tools/echo", ch2, "S256")); br.Code != "" {
			t.Error("a second user got a code without consenting (alice's consent leaked)")
		}
	})

	t.Run("AuthCodeReplay_RevokesFamilyAndAudits", func(t *testing.T) {
		t.Parallel()
		f := newSingleMCPRefreshFixture(t)
		code, v, _ := f.h.RunFlowC1Consent(f.email, topoPassword, f.agent, topoRedirect, singleMCPSlug,
			[]string{"tools/echo"}, []string{"tools/echo"})
		first := topoRedeem(t, f.h, code, v, f.agent)
		if !first.OK() {
			t.Fatalf("first redeem: %d %s", first.Status, first.Raw)
		}
		second := topoRedeem(t, f.h, code, v, f.agent)
		if second.OK() || second.Err() != "invalid_grant" {
			t.Errorf("replayed code: status %d error %q, want invalid_grant", second.Status, second.Err())
		}
		if f.active(t, first.AccessToken()) {
			t.Error("access token from a replayed code is still active")
		}
		if first.Refresh() == "" {
			t.Error("no refresh token issued to an agent registered for refresh_token")
		} else if r := f.refresh(t, first.Refresh(), "", ""); r.OK() {
			t.Error("refresh token from a replayed code still refreshes")
		}
		topoExpectAudit(t, f.h, "auth_code.reused", "for the agent", func(r topoAuditRow) bool {
			return r.ClientID == f.agent && strings.Contains(r.Detail, "code_reuse")
		})
		topoExpectAudit(t, f.h, "family.revoked", "for code reuse", func(r topoAuditRow) bool {
			return strings.Contains(r.Detail, "code_reuse")
		})
	})

	t.Run("RefreshReplay_RevokesFamilyAndAudits", func(t *testing.T) {
		t.Parallel()
		f := newSingleMCPRefreshFixture(t)
		tok := topoUserToken(t, f.h, f.email, f.agent, singleMCPSlug, []string{"tools/echo"})
		if tok.Refresh() == "" {
			t.Fatal("no refresh token issued to an agent registered for refresh_token")
		}
		rotated := f.refresh(t, tok.Refresh(), "", "")
		if !rotated.OK() {
			t.Fatalf("first refresh: %d %s", rotated.Status, rotated.Raw)
		}
		if again := f.refresh(t, tok.Refresh(), "", ""); again.OK() || again.Err() != "invalid_grant" {
			t.Errorf("reused refresh token: status %d error %q, want invalid_grant", again.Status, again.Err())
		}
		if after := f.refresh(t, rotated.Refresh(), "", ""); after.OK() {
			t.Error("the rotated refresh token survived reuse detection")
		}
		topoExpectAudit(t, f.h, "family.revoked", "for refresh reuse", func(r topoAuditRow) bool {
			return strings.Contains(r.Detail, "reuse_detection")
		})
	})

	// The page registers the agent with grant_types=[authorization_code] and
	// nothing else. RFC 7591 §2 defines grant_types as the grants the client
	// may use at the token endpoint, and the AS enforces that list for
	// client_credentials, token exchange and jwt-bearer (unauthorized_client).
	// A client that never registered refresh_token must not be handed a
	// refresh token it can then use.
	t.Run("RefreshGrantNotRegistered_IsNotHonored", func(t *testing.T) {
		t.Parallel()
		f := newSingleMCPFixture(t)
		tok := topoUserToken(t, f.h, f.email, f.agent, singleMCPSlug, []string{"tools/echo"})
		if tok.Refresh() == "" {
			return // not issued: conforming
		}
		r := f.refresh(t, tok.Refresh(), "", "")
		if r.OK() {
			t.Errorf("%s: client registered without refresh_token in grant_types received a refresh token and refreshed it (status %d); want no refresh_token issued or unauthorized_client",
				topoFindingPrefix, r.Status)
		} else if r.Err() != "unauthorized_client" {
			t.Errorf("refresh by a client without the grant: error %q, want unauthorized_client", r.Err())
		}
	})

	t.Run("ConfidentialAgent_BothAuthMethods", func(t *testing.T) {
		t.Parallel()
		f := newSingleMCPFixture(t)
		conf, secret := topoCreateClient(t, f.h, map[string]any{
			"client_name": "conf-agent", "grant_types": []string{"authorization_code", "refresh_token"},
			"response_types": []string{"code"}, "token_endpoint_auth_method": "client_secret_basic",
			"scope": "tools/echo",
		})
		redeem := func(auth topoAuth, id, sec string) topoResp {
			code, v := topoCode(t, f.h, f.email, conf, singleMCPSlug, []string{"tools/echo"})
			return topoToken(t, f.h, url.Values{
				"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {topoRedirect}, "code_verifier": {v},
			}, auth, id, sec)
		}
		for _, auth := range topoBothAuth {
			if r := redeem(auth, conf, secret); !r.OK() {
				t.Errorf("%s: redeem failed %d %s", auth, r.Status, r.Raw)
			}
			if r := redeem(auth, conf, "not-the-secret"); r.OK() || r.Err() != "invalid_client" {
				t.Errorf("%s wrong secret: status %d error %q, want invalid_client", auth, r.Status, r.Err())
			}
		}
		if r := redeem(topoAuthNone, conf, ""); r.OK() || r.Err() != "invalid_client" {
			t.Errorf("confidential client with no secret: status %d error %q, want invalid_client", r.Status, r.Err())
		}
		// A public client that presents a secret is refused, not silently upgraded.
		code, v, _ := f.h.RunFlowC1Consent(f.email, topoPassword, f.agent, topoRedirect, singleMCPSlug,
			[]string{"tools/echo"}, []string{"tools/echo"})
		pub := topoToken(t, f.h, url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {topoRedirect}, "code_verifier": {v},
		}, topoAuthPost, f.agent, "invented-secret")
		if pub.OK() || pub.Err() != "invalid_client" {
			t.Errorf("public client presenting a secret: status %d error %q, want invalid_client", pub.Status, pub.Err())
		}
	})

	t.Run("ConsentRevocation_ReachesAccessAndRefresh", func(t *testing.T) {
		t.Parallel()
		f := newSingleMCPRefreshFixture(t)
		tok := topoUserToken(t, f.h, f.email, f.agent, singleMCPSlug, []string{"tools/echo"})
		if !f.active(t, tok.AccessToken()) {
			t.Fatal("precondition: token active before revocation")
		}
		grant := topoConsentGrantID(t, f.h, f.userID, f.agent, singleMCPSlug)
		topoRevokeConsent(t, f.h, grant)
		if f.active(t, tok.AccessToken()) {
			t.Error("access token still active after its consent grant was revoked")
		}
		if tok.Refresh() == "" {
			t.Error("no refresh token issued to an agent registered for refresh_token")
		} else if r := f.refresh(t, tok.Refresh(), "", ""); r.OK() {
			t.Error("refresh token still refreshes after its consent grant was revoked")
		}
		topoExpectAudit(t, f.h, "consent_grant.revoked_admin", "naming the grant", func(r topoAuditRow) bool {
			return strings.Contains(r.Detail, "id="+grant)
		})
		// The next /authorize must ask again rather than reuse the dead grant.
		c := topoLoggedIn(t, f.h, f.email)
		_, ch := topoPKCE()
		if res := f.h.Authorize(c, topoAuthorizeParams(f.agent, topoRedirect, singleMCPSlug, "tools/echo", ch, "S256")); !res.NeedsConsent {
			t.Errorf("after revocation /authorize skipped consent: %+v", res)
		}
	})
}
