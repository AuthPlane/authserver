//go:build e2e

package scenarios

import (
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// Topology: folded-resource (docs/topologies/folded-resource.md).
//
// One Resource (mcp-gw) whose richer catalog — tool:read, tool:write,
// cache:invalidate — stands in for every internal service behind it. The AS
// sees one Resource, one consent grant, one issuance per call; there is no
// fronting and no exchange. The only authorization surface is the scope
// catalog, so the adversarial cases are all about scope: defaults for an
// omitted scope, a consent POST that tries to add a scope the request never
// asked for, a client whose ceiling is narrower than the catalog, and a scope
// that is not in the catalog at all.

type foldedFixture struct {
	h             *e2e.TestHarness
	agent         string
	userID, email string
	gwURI         string
}

var foldedCatalog = []string{"tool:read", "tool:write", "cache:invalidate"}

func newFoldedFixture(t *testing.T) *foldedFixture {
	t.Helper()
	return newFoldedFixtureWithGrants(t, []string{"authorization_code"})
}

// newFoldedRefreshFixture registers the agent for refresh_token as well: the
// AS issues and honors refresh tokens only for clients registered for that
// grant, so the subtests that exercise a refresh token need this agent.
func newFoldedRefreshFixture(t *testing.T) *foldedFixture {
	t.Helper()
	return newFoldedFixtureWithGrants(t, []string{"authorization_code", "refresh_token"})
}

func newFoldedFixtureWithGrants(t *testing.T, agentGrants []string) *foldedFixture {
	t.Helper()
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{EnableAdminAPI: true}, []string{"placeholder"})
	f := &foldedFixture{h: h, email: "folded-alice@example.com", gwURI: "https://mcp-gw.folded.test"}
	f.userID = h.CreateUser(f.email, topoPassword)
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug: "mcp-gw", URI: f.gwURI, BackendKind: "mint", DisplayName: "MCP Gateway",
		Scopes: []e2e.AdminScope{
			{Name: "tool:read", Description: "Read tools"}, {Name: "tool:write", Description: "Write tools"},
			{Name: "cache:invalidate", Description: "Invalidate cache"},
		},
	})
	f.agent = h.AdminCreatePublicClient("my-agent", agentGrants,
		strings.Join(foldedCatalog, " "), []string{topoRedirect})
	return f
}

func TestTopologyFoldedResource_Adversarial(t *testing.T) {
	t.Parallel()
	t.Run("LegitimateFlow_OneResourceOneIssuance", func(t *testing.T) {
		t.Parallel()
		f := newFoldedFixture(t)
		tok := topoUserToken(t, f.h, f.email, f.agent, "mcp-gw", []string{"tool:read", "tool:write"})
		c := parseJWTClaims(t, tok.AccessToken())
		if aud := topoAud(c); len(aud) != 1 || aud[0] != f.gwURI {
			t.Errorf("aud = %v, want [%s]", aud, f.gwURI)
		}
		if got := strings.Join(topoScopes(stringClaim(c, "scope")), " "); got != "tool:read tool:write" {
			t.Errorf("scope = %q, want exactly the consented pair", got)
		}
		gw := f.h.AdminGetResourceBySlug("mcp-gw")
		for _, row := range listIssuancesByQuery(t, f.h, "user="+f.userID) {
			if row.ResourceID != gw.ID {
				t.Errorf("issuance %s points at resource %s, not the folded gateway", row.ID, row.ResourceID)
			}
		}
		topoExpectAudit(t, f.h, "consent.granted", "resource=mcp-gw", func(r topoAuditRow) bool {
			return r.ActorID == f.userID && r.ClientID == f.agent && strings.Contains(r.Detail, "resource=mcp-gw")
		})
	})

	t.Run("OmittedScope_DefaultIsCatalogWithinCeiling", func(t *testing.T) {
		t.Parallel()
		f := newFoldedFixture(t)
		narrow := f.h.AdminCreatePublicClient("reader-agent", []string{"authorization_code"}, "tool:read", []string{topoRedirect})
		c := topoLoggedIn(t, f.h, f.email)
		v, ch := topoPKCE()
		res := f.h.Authorize(c, topoAuthorizeParams(narrow, topoRedirect, "mcp-gw", "", ch, "S256"))
		if !res.NeedsConsent {
			t.Fatalf("expected consent, got %+v", res)
		}
		offered := topoConsentOffered(t, f.h, c, res.SessionID)
		topoAssertScopeWithin(t, "offered default for a tool:read-only client", strings.Join(offered, " "), true, "tool:read")
		code := f.h.GrantConsent(c, res.SessionID, offered, false)
		tok := topoRedeem(t, f.h, code, v, narrow)
		if !tok.OK() {
			t.Fatalf("redeem: %s", tok.Raw)
		}
		topoAssertScopeWithin(t, "issued scope", tok.Scope(), true, "tool:read")
	})

	t.Run("UnderPrivilegedClient_CannotRequestBeyondCeiling", func(t *testing.T) {
		t.Parallel()
		f := newFoldedFixture(t)
		narrow := f.h.AdminCreatePublicClient("reader-agent", []string{"authorization_code"}, "tool:read", []string{topoRedirect})
		c := topoLoggedIn(t, f.h, f.email)
		_, ch := topoPKCE()
		res := f.h.Authorize(c, topoAuthorizeParams(narrow, topoRedirect, "mcp-gw", "tool:read cache:invalidate", ch, "S256"))
		if res.Error != "invalid_scope" {
			t.Errorf("reader asking for cache:invalidate: %+v, want invalid_scope", res)
		}
	})

	t.Run("ScopeOutsideCatalog_Refused", func(t *testing.T) {
		t.Parallel()
		f := newFoldedFixture(t)
		// A self-registered client carries no ceiling, so the catalog is the
		// only thing standing between it and an invented scope.
		dcr, _ := topoDCR(t, f.h, map[string]any{
			"client_name": "dcr-agent", "grant_types": []string{"authorization_code"},
			"response_types": []string{"code"}, "token_endpoint_auth_method": "none",
		})
		c := topoLoggedIn(t, f.h, f.email)
		_, ch := topoPKCE()
		res := f.h.Authorize(c, topoAuthorizeParams(dcr, topoRedirect, "mcp-gw", "tool:read db:drop", ch, "S256"))
		if res.Code != "" || res.NeedsConsent {
			t.Errorf("scope outside the folded catalog reached consent/code: %+v", res)
		}
	})

	// The consent form is user-controlled input. Ticking a scope the
	// authorization request never asked for must not add it to the grant.
	t.Run("TamperedConsentPost_CannotAddUnrequestedScope", func(t *testing.T) {
		t.Parallel()
		f := newFoldedFixture(t)
		c := topoLoggedIn(t, f.h, f.email)
		v, ch := topoPKCE()
		res := f.h.Authorize(c, topoAuthorizeParams(f.agent, topoRedirect, "mcp-gw", "tool:read", ch, "S256"))
		if !res.NeedsConsent {
			t.Fatalf("expected consent, got %+v", res)
		}
		resp := f.h.PostConsentRaw(c, res.SessionID, []string{"tool:read", "cache:invalidate"})
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		loc, _ := url.Parse(resp.Header.Get("Location"))
		code := ""
		if loc != nil {
			code = loc.Query().Get("code")
		}
		if code == "" {
			return // refused outright: conforming
		}
		tok := topoRedeem(t, f.h, code, v, f.agent)
		if !tok.OK() {
			t.Fatalf("redeem: %s (consent response %d %s)", tok.Raw, resp.StatusCode, body)
		}
		topoAssertScopeWithin(t, "tampered consent", tok.Scope(), true, "tool:read")
		gw := f.h.AdminGetResourceBySlug("mcp-gw")
		if g := findActorConsentGrant(t, f.h, f.userID, f.agent, gw.ID); g != nil {
			for _, s := range g.Scopes {
				if s != "tool:read" {
					t.Errorf("consent grant recorded unrequested scope %q", s)
				}
			}
		}
	})

	t.Run("NarrowConsent_RefreshCannotWiden", func(t *testing.T) {
		t.Parallel()
		f := newFoldedRefreshFixture(t)
		code, v, _ := f.h.RunFlowC1Consent(f.email, topoPassword, f.agent, topoRedirect, "mcp-gw",
			foldedCatalog, []string{"tool:read"})
		tok := topoRedeem(t, f.h, code, v, f.agent)
		if !tok.OK() {
			t.Fatalf("redeem: %s", tok.Raw)
		}
		topoAssertScopeWithin(t, "narrow consent", tok.Scope(), true, "tool:read")
		if tok.Refresh() == "" {
			t.Fatal("no refresh token issued to an agent registered for refresh_token")
		}
		r := topoToken(t, f.h, url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {tok.Refresh()}, "scope": {"tool:read cache:invalidate"},
		}, topoAuthNone, f.agent, "")
		if r.OK() || r.Err() != "invalid_scope" {
			t.Errorf("refresh widening to cache:invalidate: status %d error %q, want invalid_scope", r.Status, r.Err())
		}
		// And a remembered narrow consent does not silently cover a wider ask.
		c := topoLoggedIn(t, f.h, f.email)
		_, ch := topoPKCE()
		if res := f.h.Authorize(c, topoAuthorizeParams(f.agent, topoRedirect, "mcp-gw", "tool:read tool:write", ch, "S256")); res.Code != "" {
			t.Error("wider request skipped consent on the strength of a narrower grant")
		}
	})

	t.Run("RevocationReach_SingleGrantKillsEverything", func(t *testing.T) {
		t.Parallel()
		f := newFoldedRefreshFixture(t)
		tok := topoUserToken(t, f.h, f.email, f.agent, "mcp-gw", foldedCatalog)
		rsID, rsSecret := topoRSCreds(t, f.h, "mcp-gw")
		if !f.h.IntrospectToken(tok.AccessToken(), rsID, rsSecret).Active {
			t.Fatal("precondition: active")
		}
		topoRevokeConsent(t, f.h, topoConsentGrantID(t, f.h, f.userID, f.agent, "mcp-gw"))
		if f.h.IntrospectToken(tok.AccessToken(), rsID, rsSecret).Active {
			t.Error("token still active after the folded resource's only consent was revoked")
		}
		if tok.Refresh() == "" {
			t.Error("no refresh token issued to an agent registered for refresh_token")
		} else if r := topoToken(t, f.h, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.Refresh()}},
			topoAuthNone, f.agent, ""); r.OK() {
			t.Error("refresh survived consent revocation")
		}
		topoExpectAudit(t, f.h, "token.introspect_denied", "reason=issuance_revoked", func(r topoAuditRow) bool {
			return r.ClientID == rsID && strings.Contains(r.Detail, "reason=issuance_revoked")
		})
	})
}
