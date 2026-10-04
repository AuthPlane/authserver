//go:build e2e

package scenarios

import (
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// Topology: client-credentials-hop (docs/topologies/client-credentials-hop.md).
//
// The gateway (resource mcp-0, standing in for mcp-gw) receives the user's
// token from the agent, then calls the hidden internal-metrics Resource as
// itself via client_credentials. The page promises two unrelated issuances:
// the first hop carries sub = user, the second sub = client_id = gateway and
// no user context, and the AS records no link between them (revoking one
// leaves the other alone).
//
// Adversaries: the agent trying to reach the hidden API with its user token,
// the gateway trying to carry the user across the hop with token exchange
// (it was registered for client_credentials only), an under-privileged
// gateway client, and a foreign machine client aimed at the hidden API.

type ccHopFixture struct {
	h              *e2e.TestHarness
	rs             *e2e.MCPResourceServer
	agent          string
	gw, gwSecret   string
	userID, email  string
	hiddenURI      string
	rsID, rsSecret string // introspection creds for the hidden API
}

func newCCHopFixture(t *testing.T) *ccHopFixture {
	t.Helper()
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI: true, EnableClientCredentials: true, EnableTokenExchange: true,
	}, []string{"tools/echo"})
	f := &ccHopFixture{h: h, rs: servers[0], email: "cchop-alice@example.com", hiddenURI: "https://metrics.internal.test"}
	f.userID = h.CreateUser(f.email, topoPassword)
	f.agent = h.AdminCreatePublicClient("my-agent", []string{"authorization_code"}, "tools/echo", []string{topoRedirect})
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug: "internal-metrics", URI: f.hiddenURI, BackendKind: "mint", DisplayName: "Internal Metrics",
		Scopes: []e2e.AdminScope{{Name: "emit", Description: "Emit metrics"}},
	})
	// The gateway's client identity, exactly as the page registers it.
	f.gw, f.gwSecret = topoCreateClient(t, h, map[string]any{
		"client_name": "mcp-gw", "grant_types": []string{"client_credentials"},
		"token_endpoint_auth_method": "client_secret_basic", "scope": "emit",
	})
	f.rsID, f.rsSecret = topoRSCreds(t, h, "internal-metrics")
	return f
}

func TestTopologyClientCredentialsHop_Adversarial(t *testing.T) {
	t.Parallel()
	t.Run("LegitimateFlow_TwoIndependentIssuances", func(t *testing.T) {
		t.Parallel()
		f := newCCHopFixture(t)
		user := topoUserToken(t, f.h, f.email, f.agent, "mcp-0", []string{"tools/echo"})
		uc := parseJWTClaims(t, user.AccessToken())
		if stringClaim(uc, "sub") != f.userID || topoAud(uc)[0] != f.rs.URI {
			t.Errorf("first hop: sub=%q aud=%v, want user %q at %s", stringClaim(uc, "sub"), topoAud(uc), f.userID, f.rs.URI)
		}
		for _, auth := range topoBothAuth {
			hop := topoToken(t, f.h, topoCCForm(f.hiddenURI, "emit"), auth, f.gw, f.gwSecret)
			if !hop.OK() {
				t.Fatalf("%s: second hop: %d %s", auth, hop.Status, hop.Raw)
			}
			c := parseJWTClaims(t, hop.AccessToken())
			if aud := topoAud(c); len(aud) != 1 || aud[0] != f.hiddenURI {
				t.Errorf("%s: second hop aud = %v, want [%s]", auth, aud, f.hiddenURI)
			}
			if stringClaim(c, "sub") != f.gw || stringClaim(c, "client_id") != f.gw {
				t.Errorf("%s: second hop sub/client_id = %q/%q, want gateway %q", auth, stringClaim(c, "sub"), stringClaim(c, "client_id"), f.gw)
			}
			if _, has := c["act"]; has {
				t.Errorf("%s: second hop carries an act claim — user context must be dropped", auth)
			}
			if strings.Contains(hop.Raw, f.userID) {
				t.Errorf("%s: second hop mentions the user id", auth)
			}
		}
		topoExpectAudit(t, f.h, "client_credentials.issued", "for the gateway", func(r topoAuditRow) bool {
			return r.ClientID == f.gw && strings.Contains(r.Detail, "scopes=emit")
		})
		topoExpectAudit(t, f.h, "token.issued", "for the first hop", func(r topoAuditRow) bool {
			return r.ActorID == f.userID && r.ClientID == f.agent
		})
	})

	t.Run("OmittedParameters_NeverBroaderThanRegistration", func(t *testing.T) {
		t.Parallel()
		f := newCCHopFixture(t)
		r := topoToken(t, f.h, topoCCForm(f.hiddenURI, ""), topoAuthBasic, f.gw, f.gwSecret)
		if !r.OK() {
			t.Fatalf("scope omitted: %d %s", r.Status, r.Raw)
		}
		topoAssertScopeWithin(t, "scope omitted", r.Scope(), true, "emit")
		noRes := topoToken(t, f.h, topoCCForm("", "emit"), topoAuthBasic, f.gw, f.gwSecret)
		if noRes.OK() {
			for _, a := range topoAud(parseJWTClaims(t, noRes.AccessToken())) {
				if a == f.hiddenURI {
					t.Error("resource omitted still produced a hidden-API token")
				}
			}
		}
	})

	t.Run("Agent_CannotReachHiddenAPI", func(t *testing.T) {
		t.Parallel()
		f := newCCHopFixture(t)
		user := topoUserToken(t, f.h, f.email, f.agent, "mcp-0", []string{"tools/echo"})
		for _, a := range topoAud(parseJWTClaims(t, user.AccessToken())) {
			if a == f.hiddenURI {
				t.Fatal("the user's token is audienced to the hidden API")
			}
		}
		// The public agent cannot mint for the hidden API itself...
		if r := topoToken(t, f.h, topoCCForm(f.hiddenURI, "emit"), topoAuthNone, f.agent, ""); r.OK() {
			t.Errorf("public agent minted a hidden-API token: %s", r.Raw)
		}
		// ...nor ask /authorize for it on the user's behalf and get emit.
		c := topoLoggedIn(t, f.h, f.email)
		_, ch := topoPKCE()
		res := f.h.Authorize(c, topoAuthorizeParams(f.agent, topoRedirect, "internal-metrics", "emit", ch, "S256"))
		if res.Code != "" || res.NeedsConsent {
			t.Errorf("agent obtained a path to emit at the hidden API: %+v", res)
		}
	})

	t.Run("Gateway_CannotCarryUserAcrossHop", func(t *testing.T) {
		t.Parallel()
		f := newCCHopFixture(t)
		user := topoUserToken(t, f.h, f.email, f.agent, "mcp-0", []string{"tools/echo"})
		for _, auth := range topoBothAuth {
			r := topoToken(t, f.h, topoExchangeForm(user.AccessToken(), "internal-metrics", "emit"), auth, f.gw, f.gwSecret)
			if r.OK() || r.Err() != "unauthorized_client" {
				t.Errorf("%s: gateway (client_credentials only) exchanging the user's token: status %d error %q, want unauthorized_client", auth, r.Status, r.Err())
			}
		}
		topoExpectAudit(t, f.h, "token.exchange_denied", "reason=unauthorized_client", func(r topoAuditRow) bool {
			return r.ClientID == f.gw && strings.Contains(r.Detail, "reason=unauthorized_client")
		})
	})

	t.Run("UnderPrivilegedGateway_Refused", func(t *testing.T) {
		t.Parallel()
		f := newCCHopFixture(t)
		weak, weakSecret := topoCreateClient(t, f.h, map[string]any{
			"client_name": "weak-gw", "grant_types": []string{"client_credentials"},
			"token_endpoint_auth_method": "client_secret_basic", "scope": "read",
		})
		if r := topoToken(t, f.h, topoCCForm(f.hiddenURI, "emit"), topoAuthBasic, weak, weakSecret); r.OK() || r.Err() != "invalid_scope" {
			t.Errorf("gateway without emit: status %d error %q, want invalid_scope", r.Status, r.Err())
		}
	})

	t.Run("ForeignMachineClient_ScopeOutsideHiddenCatalog", func(t *testing.T) {
		t.Parallel()
		f := newCCHopFixture(t)
		foreign, foreignSecret := topoCreateClient(t, f.h, map[string]any{
			"client_name": "billing-job", "grant_types": []string{"client_credentials"},
			"token_endpoint_auth_method": "client_secret_basic", "scope": "billing:write",
		})
		r := topoToken(t, f.h, topoCCForm(f.hiddenURI, ""), topoAuthBasic, foreign, foreignSecret)
		if r.OK() {
			topoAssertScopeWithin(t, topoFindingPrefix+": foreign machine client's token for the hidden API", r.Scope(), false, "emit")
		}
	})

	t.Run("RevocationReach_HopsAreIndependent", func(t *testing.T) {
		t.Parallel()
		f := newCCHopFixture(t)
		user := topoUserToken(t, f.h, f.email, f.agent, "mcp-0", []string{"tools/echo"})
		hop := topoToken(t, f.h, topoCCForm(f.hiddenURI, "emit"), topoAuthBasic, f.gw, f.gwSecret)
		if !hop.OK() {
			t.Fatalf("second hop: %s", hop.Raw)
		}
		userRSID, userRSSecret := topoRSCreds(t, f.h, "mcp-0")
		topoRevokeConsent(t, f.h, topoConsentGrantID(t, f.h, f.userID, f.agent, "mcp-0"))
		if f.h.IntrospectToken(user.AccessToken(), userRSID, userRSSecret).Active {
			t.Error("first-hop token still active after its consent was revoked")
		}
		// Documented: no chain link, so the machine token is untouched.
		if !f.h.IntrospectToken(hop.AccessToken(), f.rsID, f.rsSecret).Active {
			t.Error("second-hop machine token died with the user's consent; the page says the hops are independent")
		}
		// Suspending the gateway is what reaches the second hop.
		topoAdminPatch(t, f.h, "/admin/clients/"+f.gw+"/suspend")
		if f.h.IntrospectToken(hop.AccessToken(), f.rsID, f.rsSecret).Active {
			t.Error("second-hop token of a suspended gateway still active")
		}
		if r := topoToken(t, f.h, topoCCForm(f.hiddenURI, "emit"), topoAuthBasic, f.gw, f.gwSecret); r.OK() {
			t.Error("suspended gateway minted a new hidden-API token")
		}
		topoExpectAudit(t, f.h, "token.introspect_denied", "reason=issuing_client_inactive", func(r topoAuditRow) bool {
			return r.ClientID == f.rsID && strings.Contains(r.Detail, "reason=issuing_client_inactive")
		})
	})
}
