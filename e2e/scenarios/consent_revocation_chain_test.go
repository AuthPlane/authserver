//go:build e2e

package scenarios

import (
	"net/http"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// Revoking a consent grant reaches every token that exists
// because of it — the client's own token, the token a service exchanged
// it for, and the token a second service exchanged that one for — at the
// two places a token is judged: /oauth/introspect and, as a subject
// token, /oauth/token. Before this, revocation stopped new mints and
// nothing else; every token already out lived to exp.
//
// The chain, over the wire:
//
//	alice → webApp (auth-code, resource mcp-0)         hop0: client webApp, aud mcp-0
//	svcB, bound to mcp-1, exchanges hop0 for mcp-1     hop1: client svcB,   aud mcp-1, consent (alice, webApp, mcp-1)
//	svcC, bound to mcp-2, exchanges hop1 for mcp-2     hop2: client svcC,   aud mcp-2, consent (alice, svcB, mcp-2)
type revocationChain struct {
	h                         *e2e.TestHarness
	rs0, rs1, rs2             *e2e.MCPResourceServer
	userID                    string
	webAppID                  string
	svcBID, svcBSecret        string
	svcCID, svcCSecret        string
	hop0                      *e2e.TokenResponse
	hop1, hop2                *e2e.TokenExchangeResponse
	grantWebAppMCP1           string // consent grant id for (alice, webApp, mcp-1)
	grantWebAppMCP0           string // consent grant id for (alice, webApp, mcp-0)
	mcp0URI, mcp1URI, mcp2URI string
}

func buildRevocationChain(t *testing.T) *revocationChain {
	t.Helper()
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI:             true,
		EnableTokenExchange:        true,
		TokenExchangeMaxChainDepth: 5,
	}, scopes, scopes, scopes)
	c := &revocationChain{h: h, rs0: servers[0], rs1: servers[1], rs2: servers[2]}
	for _, rs := range []*e2e.MCPResourceServer{c.rs0, c.rs1, c.rs2} {
		h.RegisterScope(rs.URI, "tools/echo", "Echo tool")
	}
	c.mcp0URI, c.mcp1URI, c.mcp2URI = c.rs0.URI, c.rs1.URI, c.rs2.URI

	const email, password = "alice-chain@example.com", "pass123"
	c.userID = h.CreateUser(email, password)

	c.webAppID = h.AdminCreatePublicClient("chain webapp",
		[]string{"authorization_code", "refresh_token"}, "tools/echo", nil)
	c.svcBID, c.svcBSecret = h.RegisterAgentClient(
		[]string{"urn:ietf:params:oauth:grant-type:token-exchange", "authorization_code"}, "tools/echo", "service B, is mcp-1")
	c.svcCID, c.svcCSecret = h.RegisterAgentClient(
		[]string{"urn:ietf:params:oauth:grant-type:token-exchange"}, "tools/echo", "service C, is mcp-2")
	h.AdminAddRuntimeClientID("mcp-1", c.svcBID)
	h.AdminAddRuntimeClientID("mcp-2", c.svcCID)

	// Consents: alice → webApp for mcp-1 (hop1's gate), alice → svcB for
	// mcp-2 (hop2's gate). hop0's own consent for mcp-0 comes from the
	// auth-code flow below.
	const redirect = "http://localhost:9999/callback"
	h.RunFlowC1Consent(email, password, c.webAppID, redirect, "mcp-1", scopes, scopes)
	h.RunFlowC1Consent(email, password, c.svcBID, redirect, "mcp-2", scopes, scopes)

	c.hop0 = e2e.NewMCPClient(t, h, c.rs0, c.webAppID, redirect).FullFlow(email, password, "tools/echo", false)
	if c.hop0.RefreshToken == "" {
		t.Fatal("precondition: webApp should hold a refresh token")
	}
	c.hop1 = h.TokenExchangeWithResource(c.svcBID, c.svcBSecret,
		c.hop0.AccessToken, tokenTypeAccessToken, "tools/echo", "mcp-1")
	c.hop2 = h.TokenExchangeWithResource(c.svcCID, c.svcCSecret,
		c.hop1.AccessToken, tokenTypeAccessToken, "tools/echo", "mcp-2")
	if c.hop1.AccessToken == "" || c.hop2.AccessToken == "" {
		t.Fatal("precondition: both exchange hops should succeed")
	}

	mcp0 := h.AdminGetResourceBySlug("mcp-0")
	mcp1 := h.AdminGetResourceBySlug("mcp-1")
	if g := findActorConsentGrant(t, h, c.userID, c.webAppID, mcp1.ID); g != nil {
		c.grantWebAppMCP1 = g.ID
	} else {
		t.Fatal("precondition: no consent grant for (alice, webApp, mcp-1)")
	}
	if g := findActorConsentGrant(t, h, c.userID, c.webAppID, mcp0.ID); g != nil {
		c.grantWebAppMCP0 = g.ID
	} else {
		t.Fatal("precondition: no consent grant for (alice, webApp, mcp-0)")
	}

	// Everything is live before the revoke.
	c.assertActive(t, "hop0", c.hop0.AccessToken, c.mcp0URI, true)
	c.assertActive(t, "hop1", c.hop1.AccessToken, c.mcp1URI, true)
	c.assertActive(t, "hop2", c.hop2.AccessToken, c.mcp2URI, true)
	return c
}

func (c *revocationChain) assertActive(t *testing.T, name, token, rsURI string, want bool) {
	t.Helper()
	got := c.h.IntrospectAsResourceServer(token, rsURI).Active
	if got != want {
		t.Errorf("%s introspection active = %v, want %v", name, got, want)
	}
}

func (c *revocationChain) revoke(t *testing.T, grantID string) {
	t.Helper()
	resp := c.h.AdminRequest(http.MethodDelete, "/admin/grants/consent/"+grantID, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /admin/grants/consent/%s: status %d", grantID, resp.StatusCode)
	}
}

// Revoking the grant at the root of the delegation (alice → webApp for
// mcp-1) kills hop1 and everything below it, refuses hop1 as a subject
// token, and leaves alice's own session with webApp on mcp-0 alone: that
// consent was not withdrawn.
func TestConsentRevocation_ReachesEveryHopBelowTheGrant(t *testing.T) {
	c := buildRevocationChain(t)

	c.revoke(t, c.grantWebAppMCP1)

	c.assertActive(t, "hop1", c.hop1.AccessToken, c.mcp1URI, false)
	c.assertActive(t, "hop2", c.hop2.AccessToken, c.mcp2URI, false)
	c.assertActive(t, "hop0", c.hop0.AccessToken, c.mcp0URI, true)

	// hop1 cannot seed another hop. The subject token is revoked, which
	// RFC 8693 §2.2.2 answers with invalid_grant; consent_required would
	// claim the caller could fix it by asking, and it cannot.
	oe := c.h.TokenExchangeWithResourceExpectError(c.svcCID, c.svcCSecret,
		c.hop1.AccessToken, tokenTypeAccessToken, "tools/echo", "mcp-2")
	if oe.Error != "invalid_grant" {
		t.Errorf("exchange from revoked hop1: error = %q, want invalid_grant", oe.Error)
	}

	// svcB cannot start over from alice's live hop0 either: the grant that
	// authorized that exchange is gone.
	oe = c.h.TokenExchangeWithResourceExpectError(c.svcBID, c.svcBSecret,
		c.hop0.AccessToken, tokenTypeAccessToken, "tools/echo", "mcp-1")
	if oe.Error != "consent_required" {
		t.Errorf("exchange from hop0 after revoke: error = %q, want consent_required", oe.Error)
	}

	// alice's session with webApp is untouched: it still refreshes.
	if refreshed := c.h.RefreshToken(c.hop0.RefreshToken, c.webAppID); refreshed.AccessToken == "" {
		t.Error("webApp's refresh for mcp-0 should still work; that consent was not revoked")
	}

	// The audit row reports what was reached.
	c.assertAuditDetail(t, "revoked_issuances=2", "revoked_families=0")
}

// Revoking the top-level grant (alice → webApp for mcp-0) kills the
// session itself — the access token, the refresh family — and, through
// the parent link from hop0, every token exchanged from it.
func TestConsentRevocation_TopLevelGrant_KillsSessionAndChain(t *testing.T) {
	c := buildRevocationChain(t)

	c.revoke(t, c.grantWebAppMCP0)

	c.assertActive(t, "hop0", c.hop0.AccessToken, c.mcp0URI, false)
	c.assertActive(t, "hop1", c.hop1.AccessToken, c.mcp1URI, false)
	c.assertActive(t, "hop2", c.hop2.AccessToken, c.mcp2URI, false)

	// The refresh family is revoked: webApp cannot mint a fresh first hop.
	oe := c.h.RefreshTokenExpectError(c.hop0.RefreshToken, c.webAppID)
	if oe.Error != "invalid_grant" {
		t.Errorf("refresh after top-level revoke: error = %q, want invalid_grant", oe.Error)
	}

	c.assertAuditDetail(t, "revoked_issuances=3", "revoked_families=1")
}

// A sibling grant is not collateral. A second app with its own consent
// for mcp-1, and a service token exchanged from it, survive the revoke of
// webApp's grant for the same resource.
func TestConsentRevocation_SiblingGrantUntouched(t *testing.T) {
	c := buildRevocationChain(t)
	const email, password = "alice-chain@example.com", "pass123"
	const redirect = "http://localhost:9999/callback"

	otherAppID := c.h.AdminCreatePublicClient("chain other app",
		[]string{"authorization_code"}, "tools/echo", nil)
	c.h.RunFlowC1Consent(email, password, otherAppID, redirect, "mcp-1", []string{"tools/echo"}, []string{"tools/echo"})
	otherHop0 := e2e.NewMCPClient(t, c.h, c.rs0, otherAppID, redirect).FullFlow(email, password, "tools/echo", false)
	otherHop1 := c.h.TokenExchangeWithResource(c.svcBID, c.svcBSecret,
		otherHop0.AccessToken, tokenTypeAccessToken, "tools/echo", "mcp-1")

	c.revoke(t, c.grantWebAppMCP1)

	c.assertActive(t, "hop1 (webApp's)", c.hop1.AccessToken, c.mcp1URI, false)
	c.assertActive(t, "otherHop1 (other app's, same service, same resource)", otherHop1.AccessToken, c.mcp1URI, true)
}

func (c *revocationChain) assertAuditDetail(t *testing.T, wants ...string) {
	t.Helper()
	if !auditDetailContainsAll(t, c.h, "consent_grant.revoked_admin", wants...) {
		t.Errorf("no consent_grant.revoked_admin audit row carries all of %q", wants)
	}
}

// A fronted exchange consults no consent grant — the operator's fronting
// link stands in for it — so its issuance carries no consent_client_id.
// It still dies with the grant at its root, through the parent link from
// the gateway token it was exchanged from.
func TestConsentRevocation_ReachesFrontedExchange(t *testing.T) {
	const (
		gwSlug, apiSlug = "mcp-gw", "rest-api"
		gwURI, apiURI   = "https://mcp-gw.test", "https://rest-api.test"
		redirect        = "http://localhost:9999/callback"
		email, password = "alice-fronted@example.com", "pass123"
	)
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI:             true,
		EnableTokenExchange:        true,
		TokenExchangeMaxChainDepth: 5,
	}, []string{"placeholder"})
	userID := h.CreateUser(email, password)

	gwClient := h.AdminCreatePublicClient("gateway", []string{"authorization_code"}, "A", []string{redirect})
	agentClient, agentSecret := h.AdminCreateAgentClient("fanout agent",
		[]string{"urn:ietf:params:oauth:grant-type:token-exchange"}, "AA", "fanout agent")
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug: gwSlug, URI: gwURI, BackendKind: "mint", DisplayName: "gateway",
		Scopes: []e2e.AdminScope{{Name: "A"}},
	})
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug: apiSlug, URI: apiURI, BackendKind: "mint", DisplayName: "api",
		Scopes: []e2e.AdminScope{{Name: "AA"}},
		Policy: &e2e.AdminPolicy{Exchange: e2e.AdminExchangePolicy{AllowedClientIDs: []string{agentClient}}},
	})
	h.AdminCreateFrontingLink(e2e.CreateFrontingLinkSpec{
		Source: gwSlug, Target: apiSlug, ScopeMap: map[string][]string{"A": {"AA"}},
	})

	code, verifier, _ := h.RunFlowC1Consent(email, password, gwClient, redirect, gwSlug, []string{"A"}, []string{"A"})
	gwTokens := h.ExchangeCode(code, verifier, gwClient, redirect)
	fronted := h.TokenExchangeWithResource(agentClient, agentSecret, gwTokens.AccessToken,
		tokenTypeAccessToken, "AA", apiSlug)
	if fronted.AccessToken == "" {
		t.Fatal("precondition: fronted exchange should succeed")
	}
	// A fronted token's client_id is the source slug, which introspection
	// cannot resolve to a client, so it reports inactive to everyone
	// regardless (pinned in the introspection tests). The issuance log is
	// the evidence here: the fronted row, live before, revoked after.
	api := h.AdminGetResourceBySlug(apiSlug)
	frontedRow := func() *adminIssuanceFullView {
		for _, row := range listIssuancesByQuery(t, h, "user="+userID) {
			if row.ResourceID == api.ID {
				return &row
			}
		}
		return nil
	}
	if row := frontedRow(); row == nil || row.RevokedAt != nil {
		t.Fatalf("precondition: expected a live fronted issuance, got %+v", row)
	}

	gw := h.AdminGetResourceBySlug(gwSlug)
	grant := findActorConsentGrant(t, h, userID, gwClient, gw.ID)
	if grant == nil {
		t.Fatal("precondition: no consent grant for (alice, gateway, mcp-gw)")
	}
	resp := h.AdminRequest(http.MethodDelete, "/admin/grants/consent/"+grant.ID, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: status %d", resp.StatusCode)
	}

	if h.IntrospectAsResourceServer(gwTokens.AccessToken, gwURI).Active {
		t.Error("gateway token should be revoked with its grant")
	}
	if row := frontedRow(); row == nil || row.RevokedAt == nil {
		t.Errorf("fronted issuance should be revoked through the parent link from the gateway token, got %+v", row)
	}
	oe := h.TokenExchangeWithResourceExpectError(agentClient, agentSecret, gwTokens.AccessToken,
		tokenTypeAccessToken, "AA", apiSlug)
	if oe.Error != "invalid_grant" {
		t.Errorf("fronted exchange from the revoked gateway token: error = %q, want invalid_grant", oe.Error)
	}
}
