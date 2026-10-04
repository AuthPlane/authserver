//go:build e2e

package scenarios

import (
	"net/http"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// Topology: direct-fanout (docs/topologies/direct-fanout.md).
//
// One agent, several independent Mint Resources (mcp-0 = A, mcp-1 = B,
// mcp-c = C), per-MCP consent. The page promises one token per MCP with
// aud = that MCP, a separate consent_grants row per (user, agent, MCP), and a
// per-MCP consent gate at exchange time: exchanging an A token for B without
// consent at B is consent_required.
//
// The public agent from the page covers the per-MCP flows. The cross-MCP
// exchange the page describes needs a client that can call token exchange, so
// a confidential agent with [authorization_code, token-exchange] plays it.

type fanoutFixture struct {
	h                *e2e.TestHarness
	rsA, rsB         *e2e.MCPResourceServer
	pubAgent         string
	agent, secret    string
	userID, email    string
	cURI             string
	rsBID, rsBSecret string
	rsAID, rsASecret string
}

func newFanoutFixture(t *testing.T) *fanoutFixture {
	t.Helper()
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI: true, EnableTokenExchange: true, TokenExchangeMaxChainDepth: 5,
	}, []string{"tools/echo"}, []string{"tools/echo"})
	f := &fanoutFixture{h: h, rsA: servers[0], rsB: servers[1], email: "fanout-alice@example.com", cURI: "https://mcp-c.fanout.test"}
	f.userID = h.CreateUser(f.email, topoPassword)
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug: "mcp-c", URI: f.cURI, BackendKind: "mint", DisplayName: "mcp-c",
		Scopes: []e2e.AdminScope{{Name: "tools/echo"}, {Name: "tools/db_query"}},
	})
	f.pubAgent = h.AdminCreatePublicClient("my-agent", []string{"authorization_code"}, "tools/echo tools/db_query", []string{topoRedirect})
	f.agent, f.secret = topoCreateClient(t, h, map[string]any{
		"client_name": "fanout-agent", "grant_types": []string{"authorization_code", topoGrantTE},
		"response_types": []string{"code"}, "token_endpoint_auth_method": "client_secret_basic",
		"scope": "tools/echo tools/db_query",
	})
	f.rsAID, f.rsASecret = topoRSCreds(t, h, "mcp-0")
	f.rsBID, f.rsBSecret = topoRSCreds(t, h, "mcp-1")
	return f
}

// confToken drives the auth-code flow for the confidential agent at slug.
func (f *fanoutFixture) confToken(t *testing.T, slug string, scopes []string) topoResp {
	t.Helper()
	code, v := topoCode(t, f.h, f.email, f.agent, slug, scopes)
	r := topoToken(t, f.h, map[string][]string{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {topoRedirect}, "code_verifier": {v},
	}, topoAuthBasic, f.agent, f.secret)
	if !r.OK() {
		t.Fatalf("precondition: confidential agent token at %s: %d %s", slug, r.Status, r.Raw)
	}
	return r
}

func (f *fanoutFixture) consentAt(t *testing.T, client, slug string, scopes []string) {
	t.Helper()
	topoCode(t, f.h, f.email, client, slug, scopes)
}

func TestTopologyDirectFanout_Adversarial(t *testing.T) {
	t.Parallel()
	t.Run("LegitimateFlow_OneTokenPerMCP_NotInterchangeable", func(t *testing.T) {
		t.Parallel()
		f := newFanoutFixture(t)
		a := topoUserToken(t, f.h, f.email, f.pubAgent, "mcp-0", []string{"tools/echo"})
		b := topoUserToken(t, f.h, f.email, f.pubAgent, "mcp-1", []string{"tools/echo"})
		if aud := topoAud(parseJWTClaims(t, a.AccessToken())); len(aud) != 1 || aud[0] != f.rsA.URI {
			t.Errorf("A token aud = %v", aud)
		}
		if aud := topoAud(parseJWTClaims(t, b.AccessToken())); len(aud) != 1 || aud[0] != f.rsB.URI {
			t.Errorf("B token aud = %v", aud)
		}
		mcB := e2e.NewMCPClient(t, f.h, f.rsB, f.pubAgent, topoRedirect)
		if st, _ := mcB.CallTool("/tools/echo", a.AccessToken(), `"x"`); st != http.StatusUnauthorized {
			t.Errorf("A token accepted at B: status %d, want 401", st)
		}
		if st, _ := mcB.CallTool("/tools/echo", b.AccessToken(), `"x"`); st != http.StatusOK {
			t.Errorf("B token at B: status %d, want 200", st)
		}
		grants := listUserGrants(t, f.h, f.userID).ConsentGrants
		n := 0
		for _, g := range grants {
			if g.ClientID == f.pubAgent {
				n++
			}
		}
		if n != 2 {
			t.Errorf("consent_grants rows for (user, agent) = %d, want 2 (one per MCP)", n)
		}
	})

	t.Run("DenyAtB_IsIndependent", func(t *testing.T) {
		t.Parallel()
		f := newFanoutFixture(t)
		a := topoUserToken(t, f.h, f.email, f.pubAgent, "mcp-0", []string{"tools/echo"})
		code, _, _ := f.h.RunFlowC1Consent(f.email, topoPassword, f.pubAgent, topoRedirect, "mcp-1", []string{"tools/echo"}, nil)
		if code != "" {
			t.Fatal("deny at B still produced a code")
		}
		if !f.h.IntrospectToken(a.AccessToken(), f.rsAID, f.rsASecret).Active {
			t.Error("denying B killed the A token")
		}
		// audit-events.md documents consent.denied with the session key only
		// (no actor, no client), so that is all this can pin.
		topoExpectAudit(t, f.h, "consent.denied", "with session=", func(r topoAuditRow) bool {
			return strings.Contains(r.Detail, "session=")
		})
	})

	t.Run("CrossMCPExchange_WithoutConsentAtB_ConsentRequired", func(t *testing.T) {
		t.Parallel()
		f := newFanoutFixture(t)
		a := f.confToken(t, "mcp-0", []string{"tools/echo"})
		for _, auth := range topoBothAuth {
			r := topoToken(t, f.h, topoExchangeForm(a.AccessToken(), "mcp-1", "tools/echo"), auth, f.agent, f.secret)
			if r.OK() || r.Err() != "consent_required" {
				t.Errorf("%s: A→B without consent at B: status %d error %q, want consent_required", auth, r.Status, r.Err())
			}
		}
		topoExpectAudit(t, f.h, "token.exchange_denied", "reason=consent_required", func(r topoAuditRow) bool {
			return r.ClientID == f.agent && strings.Contains(r.Detail, "reason=consent_required")
		})
	})

	t.Run("CrossMCPExchange_WithConsentAtB_DocumentedShape", func(t *testing.T) {
		t.Parallel()
		f := newFanoutFixture(t)
		a := f.confToken(t, "mcp-0", []string{"tools/echo"})
		f.consentAt(t, f.agent, "mcp-1", []string{"tools/echo"})
		for _, auth := range topoBothAuth {
			r := topoToken(t, f.h, topoExchangeForm(a.AccessToken(), "mcp-1", "tools/echo"), auth, f.agent, f.secret)
			if !r.OK() {
				t.Fatalf("%s: A→B with consent at B: %d %s", auth, r.Status, r.Raw)
			}
			c := parseJWTClaims(t, r.AccessToken())
			if aud := topoAud(c); len(aud) != 1 || aud[0] != f.rsB.URI {
				t.Errorf("%s: aud = %v, want [%s]", auth, aud, f.rsB.URI)
			}
			if stringClaim(c, "sub") != f.userID || stringClaim(c, "client_id") != f.agent || stringClaim(c, "scope") != "tools/echo" {
				t.Errorf("%s: sub/client_id/scope = %q/%q/%q", auth, stringClaim(c, "sub"), stringClaim(c, "client_id"), stringClaim(c, "scope"))
			}
		}
		topoExpectAudit(t, f.h, "token.exchanged", "type=mint_dispatch chain_kind=direct resource=mcp-1", func(r topoAuditRow) bool {
			return r.ActorID == f.userID && r.ClientID == f.agent &&
				topoDetailHas(r.Detail, "type=mint_dispatch", "chain_kind=direct", "resource=mcp-1", "subject_client="+f.agent)
		})
	})

	// RFC 8693 lets scope be omitted and leaves the result to the AS. The
	// fronted path derives it from the subject (fixed at this release); the
	// direct path must likewise yield a documented, non-empty scope bounded by
	// the consent at B — or refuse — never a silently scope-less token.
	t.Run("CrossMCPExchange_OmittedScope", func(t *testing.T) {
		t.Parallel()
		f := newFanoutFixture(t)
		a := f.confToken(t, "mcp-0", []string{"tools/echo"})
		f.consentAt(t, f.agent, "mcp-1", []string{"tools/echo"})
		r := topoToken(t, f.h, topoExchangeForm(a.AccessToken(), "mcp-1", ""), topoAuthBasic, f.agent, f.secret)
		if !r.OK() {
			return // refused: conforming
		}
		got := stringClaim(parseJWTClaims(t, r.AccessToken()), "scope")
		topoAssertScopeWithin(t, topoFindingPrefix+": direct exchange with scope omitted", got, true, "tools/echo")
	})

	t.Run("CrossMCPExchange_OmittedResource_NoCrossReach", func(t *testing.T) {
		t.Parallel()
		f := newFanoutFixture(t)
		a := f.confToken(t, "mcp-0", []string{"tools/echo"})
		f.consentAt(t, f.agent, "mcp-1", []string{"tools/echo"})
		r := topoToken(t, f.h, topoExchangeForm(a.AccessToken(), "", "tools/echo"), topoAuthBasic, f.agent, f.secret)
		if r.OK() {
			for _, aud := range topoAud(parseJWTClaims(t, r.AccessToken())) {
				if aud == f.rsB.URI || aud == f.cURI {
					t.Errorf("resource omitted produced a token for another MCP: %s", aud)
				}
			}
		} else if r.Err() != "access_denied" {
			t.Errorf("resource omitted: error %q, want access_denied (self-exchange is off by default)", r.Err())
		}
	})

	t.Run("UnderPrivileged_ScopeBeyondSubjectOrConsent", func(t *testing.T) {
		t.Parallel()
		f := newFanoutFixture(t)
		a := f.confToken(t, "mcp-0", []string{"tools/echo"})
		f.consentAt(t, f.agent, "mcp-c", []string{"tools/echo"})
		r := topoToken(t, f.h, topoExchangeForm(a.AccessToken(), "mcp-c", "tools/echo tools/db_query"), topoAuthBasic, f.agent, f.secret)
		if r.OK() {
			t.Fatalf("widened to tools/db_query at C: %s", r.Raw)
		}
		if r.Err() != "invalid_scope" && r.Err() != "consent_required" {
			t.Errorf("error %q, want invalid_scope or consent_required", r.Err())
		}
		if bogus := topoToken(t, f.h, topoExchangeForm(a.AccessToken(), "mcp-c", "admin"), topoAuthBasic, f.agent, f.secret); bogus.OK() || bogus.Err() != "invalid_scope" {
			t.Errorf("scope outside C's catalog: status %d error %q, want invalid_scope", bogus.Status, bogus.Err())
		}
	})

	t.Run("ForeignAgent_CannotRideTheUsersConsent", func(t *testing.T) {
		t.Parallel()
		f := newFanoutFixture(t)
		a := f.confToken(t, "mcp-0", []string{"tools/echo"})
		f.consentAt(t, f.agent, "mcp-1", []string{"tools/echo"})
		foreign, foreignSecret := topoCreateClient(t, f.h, map[string]any{
			"client_name": "foreign-agent", "grant_types": []string{topoGrantTE},
			"token_endpoint_auth_method": "client_secret_post", "scope": "tools/echo",
		})
		for _, auth := range topoBothAuth {
			r := topoToken(t, f.h, topoExchangeForm(a.AccessToken(), "mcp-1", "tools/echo"), auth, foreign, foreignSecret)
			if r.OK() || r.Err() != "access_denied" {
				t.Errorf("%s: foreign client exchanging the agent's token: status %d error %q, want access_denied", auth, r.Status, r.Err())
			}
			if r := topoToken(t, f.h, topoExchangeForm(a.AccessToken(), "mcp-1", ""), auth, foreign, foreignSecret); r.OK() {
				t.Errorf("%s: foreign client with scope omitted obtained a B token", auth)
			}
		}
		topoExpectAudit(t, f.h, "token.exchange_denied", "reason=cross_client_not_authorized", func(r topoAuditRow) bool {
			return r.ClientID == foreign && strings.Contains(r.Detail, "reason=cross_client_not_authorized")
		})
	})

	t.Run("ReExchange_ExchangedTokenDoesNotReachUnconsentedMCP", func(t *testing.T) {
		t.Parallel()
		f := newFanoutFixture(t)
		a := f.confToken(t, "mcp-0", []string{"tools/echo"})
		f.consentAt(t, f.agent, "mcp-1", []string{"tools/echo"})
		b := topoToken(t, f.h, topoExchangeForm(a.AccessToken(), "mcp-1", "tools/echo"), topoAuthBasic, f.agent, f.secret)
		if !b.OK() {
			t.Fatalf("A→B: %s", b.Raw)
		}
		for _, scope := range []string{"tools/echo", ""} {
			r := topoToken(t, f.h, topoExchangeForm(b.AccessToken(), "mcp-c", scope), topoAuthBasic, f.agent, f.secret)
			if r.OK() {
				t.Errorf("B token (scope %q) re-exchanged to C without consent at C", scope)
			}
		}
	})

	t.Run("RevocationReach_ConsentAtB", func(t *testing.T) {
		t.Parallel()
		f := newFanoutFixture(t)
		a := f.confToken(t, "mcp-0", []string{"tools/echo"})
		f.consentAt(t, f.agent, "mcp-1", []string{"tools/echo"})
		b := topoToken(t, f.h, topoExchangeForm(a.AccessToken(), "mcp-1", "tools/echo"), topoAuthBasic, f.agent, f.secret)
		if !b.OK() {
			t.Fatalf("A→B: %s", b.Raw)
		}
		topoRevokeConsent(t, f.h, topoConsentGrantID(t, f.h, f.userID, f.agent, "mcp-1"))
		if f.h.IntrospectToken(b.AccessToken(), f.rsBID, f.rsBSecret).Active {
			t.Error("B token still active after consent at B was revoked")
		}
		if !f.h.IntrospectToken(a.AccessToken(), f.rsAID, f.rsASecret).Active {
			t.Error("revoking consent at B killed the A token (the MCPs are independent)")
		}
		if r := topoToken(t, f.h, topoExchangeForm(a.AccessToken(), "mcp-1", "tools/echo"), topoAuthBasic, f.agent, f.secret); r.OK() || r.Err() != "consent_required" {
			t.Errorf("A→B after revocation: status %d error %q, want consent_required", r.Status, r.Err())
		}
		topoExpectAudit(t, f.h, "consent_grant.revoked_admin", "with revoked_issuances", func(r topoAuditRow) bool {
			return strings.Contains(r.Detail, "revoked_issuances=") && !strings.Contains(r.Detail, "failed")
		})
	})

	// Disabling a user makes their tokens introspect inactive
	// (subject_inactive). A token that answers inactive must not seed a
	// fresh one through token exchange.
	t.Run("DisabledUser_TokenCannotSeedExchange", func(t *testing.T) {
		t.Parallel()
		f := newFanoutFixture(t)
		a := f.confToken(t, "mcp-0", []string{"tools/echo"})
		f.consentAt(t, f.agent, "mcp-1", []string{"tools/echo"})
		f.h.DisableUser(f.userID)
		if f.h.IntrospectToken(a.AccessToken(), f.rsAID, f.rsASecret).Active {
			t.Fatal("precondition: disabled user's token should introspect inactive")
		}
		r := topoToken(t, f.h, topoExchangeForm(a.AccessToken(), "mcp-1", "tools/echo"), topoAuthBasic, f.agent, f.secret)
		if r.OK() {
			exp := parseJWTClaims(t, r.AccessToken())["exp"]
			t.Errorf("%s: disabled user's token (inactive at introspection) exchanged for a fresh B token (exp=%v); a resource server validating the JWT locally accepts it",
				topoFindingPrefix, exp)
		}
	})
}
