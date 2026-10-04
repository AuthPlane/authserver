//go:build e2e

package scenarios

import (
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// Topology: mcp-gateway-mint (docs/topologies/mcp-gateway-mint.md).
//
// Configured exactly as the page's REST walkthrough does it: resources mcp-gw
// (A B C) and rest-api (AA BB CC), fronting link mcp-gw → rest-api with
// scope_map A→AA, B→BB, C→CC, and the gateway registered as a confidential
// client [client_credentials, token-exchange] with scope "A B C" and
// client_secret_basic. The page sets no policy.exchange.allowed_client_ids.
// The agent is an ordinary public client; the user consents at mcp-gw only.
//
// The page promises: the gateway exchanges the agent's bearer for a rest-api
// token with client_id = "mcp-gw" (Option β), act.sub = mcp-gw and
// act.act.sub = the original agent, scope translated through the map; the
// agent never sees rest-api ("full encapsulation"); the per-MCP consent at
// the source is required; token.exchanged carries type=mint_dispatch
// chain_kind=fronted via_link=mcp-gw->rest-api.

type gwMintFixture struct {
	h              *e2e.TestHarness
	agent          string
	gw, gwSecret   string
	userID, email  string
	gwURI, apiURI  string
	rsID, rsSecret string // hidden rest-api's introspection creds
}

func newGWMintFixture(t *testing.T) *gwMintFixture {
	t.Helper()
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI: true, EnableTokenExchange: true, EnableClientCredentials: true, TokenExchangeMaxChainDepth: 5,
	}, []string{"placeholder"})
	f := &gwMintFixture{h: h, email: "gwmint-alice@example.com",
		gwURI: "https://mcp-gw.gwmint.test", apiURI: "https://rest-api.gwmint.test"}
	f.userID = h.CreateUser(f.email, topoPassword)
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug: "mcp-gw", URI: f.gwURI, BackendKind: "mint", DisplayName: "MCP Gateway",
		Scopes: []e2e.AdminScope{{Name: "A"}, {Name: "B"}, {Name: "C"}},
	})
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug: "rest-api", URI: f.apiURI, BackendKind: "mint", DisplayName: "Hidden REST API",
		Scopes: []e2e.AdminScope{{Name: "AA"}, {Name: "BB"}, {Name: "CC"}},
	})
	h.AdminCreateFrontingLink(e2e.CreateFrontingLinkSpec{
		Source: "mcp-gw", Target: "rest-api",
		ScopeMap: map[string][]string{"A": {"AA"}, "B": {"BB"}, "C": {"CC"}},
	})
	f.gw, f.gwSecret = topoCreateClient(t, h, map[string]any{
		"client_name": "mcp-gw", "grant_types": []string{"client_credentials", topoGrantTE},
		"token_endpoint_auth_method": "client_secret_basic", "scope": "A B C",
	})
	f.agent = h.AdminCreatePublicClient("my-agent", []string{"authorization_code"}, "A B C", []string{topoRedirect})
	f.rsID, f.rsSecret = topoRSCreds(t, h, "rest-api")
	// The gateway declares itself as mcp-gw's runtime client — the step that
	// lets it, and only it, drive exchanges through the fronting link.
	h.AdminAddRuntimeClientID("mcp-gw", f.gw)
	return f
}

// userGWToken is the agent's bearer for mcp-gw carrying scopes.
func (f *gwMintFixture) userGWToken(t *testing.T, scopes ...string) string {
	t.Helper()
	return topoUserToken(t, f.h, f.email, f.agent, "mcp-gw", scopes).AccessToken()
}

func (f *gwMintFixture) exchange(t *testing.T, auth topoAuth, subject, resource, scope string) topoResp {
	t.Helper()
	return topoToken(t, f.h, topoExchangeForm(subject, resource, scope), auth, f.gw, f.gwSecret)
}

func TestTopologyMCPGatewayMint_Adversarial(t *testing.T) {
	t.Parallel()
	t.Run("LegitimateFlow_DocumentedTokenShape", func(t *testing.T) {
		t.Parallel()
		f := newGWMintFixture(t)
		sub := f.userGWToken(t, "A", "B")
		for _, auth := range topoBothAuth {
			r := f.exchange(t, auth, sub, "rest-api", "AA")
			if !r.OK() {
				t.Fatalf("%s: gateway exchange: %d %s", auth, r.Status, r.Raw)
			}
			c := parseJWTClaims(t, r.AccessToken())
			if aud := topoAud(c); len(aud) != 1 || aud[0] != f.apiURI {
				t.Errorf("%s: aud = %v, want [%s]", auth, aud, f.apiURI)
			}
			if stringClaim(c, "client_id") != "mcp-gw" {
				t.Errorf("%s: client_id = %q, want the source slug mcp-gw (Option β)", auth, stringClaim(c, "client_id"))
			}
			if stringClaim(c, "scope") != "AA" || stringClaim(c, "sub") != f.userID {
				t.Errorf("%s: scope/sub = %q/%q, want AA/%s", auth, stringClaim(c, "scope"), stringClaim(c, "sub"), f.userID)
			}
			if topoActSub(c, 1) != "mcp-gw" {
				t.Errorf("%s: act.sub = %q, want mcp-gw", auth, topoActSub(c, 1))
			}
		}
		topoExpectAudit(t, f.h, "token.exchanged", "type=mint_dispatch chain_kind=fronted via_link=mcp-gw->rest-api", func(r topoAuditRow) bool {
			return r.ActorID == f.userID && r.ClientID == f.gw &&
				topoDetailHas(r.Detail, "type=mint_dispatch", "chain_kind=fronted", "via_link=mcp-gw->rest-api", "subject_client="+f.agent)
		})
	})

	// The page: "act.act.sub = <original agent> ... The act.act chain anchors
	// audit back to the agent even though the gateway authenticated to
	// /oauth/token as itself." In the page's own topology the gateway and the
	// agent are different clients.
	t.Run("ActChain_AnchorsTheOriginalAgent", func(t *testing.T) {
		t.Parallel()
		f := newGWMintFixture(t)
		r := f.exchange(t, topoAuthBasic, f.userGWToken(t, "A"), "rest-api", "AA")
		if !r.OK() {
			t.Fatalf("exchange: %s", r.Raw)
		}
		c := parseJWTClaims(t, r.AccessToken())
		if got := topoActSub(c, 2); got != f.agent {
			t.Errorf("%s: act.act.sub = %q, want the original agent %q (the gateway's own OAuth client_id is %q); the agent is absent from the downstream token",
				topoFindingPrefix, got, f.agent, f.gw)
		}
	})

	// The page's sequence diagram has the gateway send its inbound
	// X-Requested-Scope verbatim: "subject_token = agent bearer, resource =
	// rest-api, scope = A", answered with "scope=AA".
	// The page's request names the target-side scope (AA); a source-side
	// name (A) is refused because rest-api declares no scope A.
	t.Run("DocumentedRequest_TargetSideScopeName", func(t *testing.T) {
		t.Parallel()
		f := newGWMintFixture(t)
		sub := f.userGWToken(t, "A")
		r := f.exchange(t, topoAuthBasic, sub, "rest-api", "AA")
		if !r.OK() {
			t.Fatalf("the documented request (scope=AA) is refused: %d %s %q", r.Status, r.Err(), r.str("error_description"))
		}
		if got := stringClaim(parseJWTClaims(t, r.AccessToken()), "scope"); got != "AA" {
			t.Errorf("documented request: scope = %q, want AA", got)
		}
		if src := f.exchange(t, topoAuthBasic, sub, "rest-api", "A"); src.OK() || src.Err() != "invalid_scope" {
			t.Errorf("source-side scope name: %d %s, want invalid_scope as the page states", src.Status, src.Err())
		}
	})

	t.Run("OmittedScope_DerivedFromSubject_NeverWider", func(t *testing.T) {
		t.Parallel()
		f := newGWMintFixture(t)
		r := f.exchange(t, topoAuthBasic, f.userGWToken(t, "A", "B"), "rest-api", "")
		if !r.OK() {
			t.Fatalf("scope omitted: %d %s", r.Status, r.Raw)
		}
		got := stringClaim(parseJWTClaims(t, r.AccessToken()), "scope")
		topoAssertScopeWithin(t, "omitted scope", got, true, "AA", "BB")
		if strings.Join(topoScopes(got), " ") != "AA BB" {
			t.Errorf("omitted scope derived %q, want AA BB", got)
		}
	})

	t.Run("OmittedResource_NoPathToHiddenAPI", func(t *testing.T) {
		t.Parallel()
		f := newGWMintFixture(t)
		sub := f.userGWToken(t, "A")
		for _, scope := range []string{"", "A", "AA"} {
			r := f.exchange(t, topoAuthBasic, sub, "", scope)
			if r.OK() {
				for _, a := range topoAud(parseJWTClaims(t, r.AccessToken())) {
					if a == f.apiURI {
						t.Errorf("resource omitted (scope %q) reached rest-api", scope)
					}
				}
			}
		}
	})

	t.Run("UnderPrivilegedSubject_CannotReachUnmappedTarget", func(t *testing.T) {
		t.Parallel()
		f := newGWMintFixture(t)
		sub := f.userGWToken(t, "A")
		for _, scope := range []string{"BB", "AA BB", "CC"} {
			r := f.exchange(t, topoAuthBasic, sub, "rest-api", scope)
			if r.OK() || r.Err() != "invalid_scope" {
				t.Errorf("subject holding only A asking %q: status %d error %q, want invalid_scope", scope, r.Status, r.Err())
			}
		}
		if r := f.exchange(t, topoAuthBasic, sub, "rest-api", "DD"); r.OK() || r.Err() != "invalid_scope" {
			t.Errorf("scope outside rest-api's catalog: status %d error %q, want invalid_scope", r.Status, r.Err())
		}
		topoExpectAudit(t, f.h, "token.exchange_denied", "reason=fronting_subject_scope_insufficient", func(r topoAuditRow) bool {
			return r.ClientID == f.gw && strings.Contains(r.Detail, "reason=fronting_subject_scope_insufficient")
		})
	})

	// "The agent never sees the hidden Resource" — full encapsulation. The
	// fronting link names two resources and no client, and the page sets no
	// allowed_client_ids, so this probes who else can drive the fronted
	// exchange: an agent registered through open DCR (the default) with the
	// token-exchange grant, holding nothing but its own consented mcp-gw token.
	t.Run("ForeignAgent_DCRWithTokenExchange_CannotBypassGateway", func(t *testing.T) {
		t.Parallel()
		f := newGWMintFixture(t)
		rogue, rogueSecret := topoDCR(t, f.h, map[string]any{
			"client_name": "helpful-agent", "grant_types": []string{"authorization_code", topoGrantTE},
			"response_types": []string{"code"}, "token_endpoint_auth_method": "client_secret_post",
		})
		code, v := topoCode(t, f.h, f.email, rogue, "mcp-gw", []string{"A"})
		own := topoToken(t, f.h, map[string][]string{
			"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {topoRedirect}, "code_verifier": {v},
		}, topoAuthPost, rogue, rogueSecret)
		if !own.OK() {
			t.Fatalf("precondition: rogue's own mcp-gw token: %s", own.Raw)
		}
		for _, scope := range []string{"AA", ""} {
			r := topoToken(t, f.h, topoExchangeForm(own.AccessToken(), "rest-api", scope), topoAuthPost, rogue, rogueSecret)
			if r.OK() {
				c := parseJWTClaims(t, r.AccessToken())
				t.Errorf("%s: a DCR-registered client that is not the gateway exchanged its own mcp-gw token for the hidden rest-api (scope param %q): aud=%v scope=%q client_id=%q act=%v — it bypasses the gateway and is stamped client_id=mcp-gw",
					topoFindingPrefix, scope, topoAud(c), stringClaim(c, "scope"), stringClaim(c, "client_id"), c["act"])
			}
		}
		// The same client presenting the *agent's* token (e.g. a second MCP
		// the bearer leaked to) — the gateway is still not consulted.
		r := topoToken(t, f.h, topoExchangeForm(f.userGWToken(t, "A"), "rest-api", "AA"), topoAuthPost, rogue, rogueSecret)
		if r.OK() {
			t.Errorf("%s: a client other than the gateway exchanged the agent's mcp-gw bearer for rest-api", topoFindingPrefix)
		}
	})

	// With the operator gate set the same foreign client is refused: the
	// control exists, the documented configuration just does not use it.
	t.Run("ForeignAgent_RefusedWhenGatewayAllowlisted", func(t *testing.T) {
		t.Parallel()
		f := newGWMintFixture(t)
		f.h.AdminAddAllowedClient("rest-api", f.gw)
		rogue, rogueSecret := topoCreateClient(t, f.h, map[string]any{
			"client_name": "other-exchanger", "grant_types": []string{topoGrantTE},
			"token_endpoint_auth_method": "client_secret_basic", "scope": "A",
		})
		sub := f.userGWToken(t, "A")
		for _, auth := range topoBothAuth {
			if r := topoToken(t, f.h, topoExchangeForm(sub, "rest-api", "AA"), auth, rogue, rogueSecret); r.OK() || r.Err() != "access_denied" {
				t.Errorf("%s: non-allowlisted client: status %d error %q, want access_denied", auth, r.Status, r.Err())
			}
		}
		if r := f.exchange(t, topoAuthBasic, sub, "rest-api", "AA"); !r.OK() {
			t.Errorf("allowlisted gateway refused: %s", r.Raw)
		}
		topoExpectAudit(t, f.h, "token.exchange_denied", "reason=operator_gate_denied", func(r topoAuditRow) bool {
			return r.ClientID == rogue && strings.Contains(r.Detail, "reason=operator_gate_denied")
		})
	})

	t.Run("NoUser_GatewayMachineTokenAsSubject_Observed", func(t *testing.T) {
		t.Parallel()
		f := newGWMintFixture(t)
		// The gateway holds client_credentials with scope "A B C" and the
		// source audience is registerable: a user-less token for mcp-gw.
		cc := topoToken(t, f.h, topoCCForm(f.gwURI, "A B C"), topoAuthBasic, f.gw, f.gwSecret)
		if !cc.OK() {
			t.Skipf("gateway cannot mint for mcp-gw: %s", cc.Raw)
		}
		r := f.exchange(t, topoAuthBasic, cc.AccessToken(), "rest-api", "")
		if r.OK() {
			c := parseJWTClaims(t, r.AccessToken())
			t.Logf("note: the gateway turned its own client_credentials token into a rest-api token (sub=%q scope=%q) with no user; per-user audit is lost on this path",
				stringClaim(c, "sub"), stringClaim(c, "scope"))
		}
	})

	t.Run("ReExchange_DownstreamTokenCannotTravelFurther", func(t *testing.T) {
		t.Parallel()
		f := newGWMintFixture(t)
		down := f.exchange(t, topoAuthBasic, f.userGWToken(t, "A", "B"), "rest-api", "AA BB")
		if !down.OK() {
			t.Fatalf("exchange: %s", down.Raw)
		}
		for _, target := range []string{"mcp-gw", "rest-api"} {
			for _, scope := range []string{"", "A", "AA"} {
				if r := f.exchange(t, topoAuthBasic, down.AccessToken(), target, scope); r.OK() {
					t.Errorf("downstream token re-exchanged to %s (scope %q)", target, scope)
				}
			}
		}
	})

	// The page's validation story for the hidden API is "an AS-issued JWT"; an
	// RFC 7662 resource server asks /oauth/introspect. The hidden API's own
	// bound credentials must see the legitimate token as active.
	t.Run("HiddenAPIIntrospection_SeesFrontedTokenActive", func(t *testing.T) {
		t.Parallel()
		f := newGWMintFixture(t)
		r := f.exchange(t, topoAuthBasic, f.userGWToken(t, "A"), "rest-api", "AA")
		if !r.OK() {
			t.Fatalf("exchange: %s", r.Raw)
		}
		if !f.h.IntrospectToken(r.AccessToken(), f.rsID, f.rsSecret).Active {
			t.Errorf("%s: rest-api's runtime-bound credentials introspect a freshly issued, legitimate fronted token as inactive (client_id=mcp-gw names no OAuth client, so the issuing-client check fails)",
				topoFindingPrefix)
		}
	})

	t.Run("RevocationReach_ConsentAtSource", func(t *testing.T) {
		t.Parallel()
		f := newGWMintFixture(t)
		sub := f.userGWToken(t, "A")
		down := f.exchange(t, topoAuthBasic, sub, "rest-api", "AA")
		if !down.OK() {
			t.Fatalf("exchange: %s", down.Raw)
		}
		topoRevokeConsent(t, f.h, topoConsentGrantID(t, f.h, f.userID, f.agent, "mcp-gw"))
		if r := f.exchange(t, topoAuthBasic, sub, "rest-api", "AA"); r.OK() || r.Err() != "invalid_grant" {
			t.Errorf("exchange from a revoked source token: status %d error %q, want invalid_grant", r.Status, r.Err())
		}
		api := f.h.AdminGetResourceBySlug("rest-api")
		for _, row := range listIssuancesByQuery(t, f.h, "user="+f.userID) {
			if row.ResourceID == api.ID && row.RevokedAt == nil {
				t.Errorf("fronted issuance %s survived revocation of the source consent", row.ID)
			}
		}
		topoExpectAudit(t, f.h, "token.exchange_denied", "reason=subject_token_revoked", func(r topoAuditRow) bool {
			return r.ClientID == f.gw && strings.Contains(r.Detail, "reason=subject_token_revoked")
		})
	})

	// Suspending the agent makes its tokens introspect inactive
	// (issuing_client_inactive). The gateway must not keep turning them
	// into fresh hidden-API tokens.
	t.Run("RevocationReach_SuspendedAgent", func(t *testing.T) {
		t.Parallel()
		f := newGWMintFixture(t)
		sub := f.userGWToken(t, "A")
		topoAdminPatch(t, f.h, "/admin/clients/"+f.agent+"/suspend")
		gwRS, gwRSSecret := topoRSCreds(t, f.h, "mcp-gw")
		if f.h.IntrospectToken(sub, gwRS, gwRSSecret).Active {
			t.Fatal("precondition: a suspended agent's token introspects inactive")
		}
		if r := f.exchange(t, topoAuthBasic, sub, "rest-api", "AA"); r.OK() {
			t.Errorf("%s: the gateway exchanged a suspended agent's token (inactive at introspection) for a fresh rest-api token", topoFindingPrefix)
		}
	})

	t.Run("RevocationReach_DisabledUser", func(t *testing.T) {
		t.Parallel()
		f := newGWMintFixture(t)
		sub := f.userGWToken(t, "A")
		f.h.DisableUser(f.userID)
		if r := f.exchange(t, topoAuthBasic, sub, "rest-api", "AA"); r.OK() {
			t.Errorf("%s: the gateway exchanged a disabled user's token for a fresh rest-api token", topoFindingPrefix)
		}
	})
}
