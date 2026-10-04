//go:build e2e

package scenarios

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// Topology: broker-mcp (docs/topologies/broker-mcp.md).
//
// A Broker Resource (google-cal, provider google = the harness's mock
// upstream) that the agent reaches directly, no gateway. The page's
// configuration is provider + broker resource + a public agent, and its flow
// starts with /authorize?resource=google-cal.
//
// The direct (non-fronted) broker dispatch is what the code actually runs
// when the subject token's aud does not resolve to a Mint Resource — i.e. a
// token minted with resource omitted (aud = issuer). Its gate is agent
// attestation: the calling client must be bound, via policy.runtime.client_ids,
// to a Mint Resource (cal-mcp here) at which the user consented to that
// client, covering every requested scope; then the three bounds
// requested ⊆ consent ⊆ broker grant apply.

const brokerMCPUpstreamToken = "goog_brokermcp_upstream_token"

type brokerMCPFixture struct {
	h             *e2e.TestHarness
	pubAgent      string
	agent, secret string // confidential agent bound to cal-mcp
	userID, email string
}

func newBrokerMCPFixture(t *testing.T) *brokerMCPFixture {
	t.Helper()
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI: true, EnableTokenExchange: true, TokenExchangeMaxChainDepth: 5,
		Connectors: []e2e.ConnectorConfig{{
			Service: "google", Scopes: []string{"calendar.readonly", "calendar.events"},
			AccessToken: brokerMCPUpstreamToken, RefreshToken: brokerMCPUpstreamToken, ExpiresIn: 3600,
		}},
	}, []string{"placeholder"})
	f := &brokerMCPFixture{h: h, email: "brokermcp-alice@example.com"}
	f.userID = h.CreateUser(f.email, topoPassword)
	mock := h.MockUpstreamURL("google")
	h.AdminCreateBrokerProvider(e2e.CreateBrokerProviderSpec{
		Slug: "google", DisplayName: "Google", Protocol: "oauth",
		ConfigData: map[string]any{
			"client_id": "mock-google-client", "client_secret_ref": "CONNECTOR_GOOGLE_SECRET",
			"authorize_url": mock + "/authorize", "token_url": mock + "/token",
		},
	})
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug: "google-cal", URI: "https://google-cal.broker.example.test", BackendKind: "broker",
		BrokerProviderSlug: "google", DisplayName: "Google Calendar",
		Scopes: []e2e.AdminScope{
			{Name: "tool:list", Upstream: "calendar.readonly"},
			{Name: "tool:create", Upstream: "calendar.events"},
		},
	})
	f.pubAgent = h.AdminCreatePublicClient("my-agent", []string{"authorization_code"}, "tool:list tool:create", []string{topoRedirect})
	f.agent, f.secret = topoCreateClient(t, h, map[string]any{
		"client_name": "cal-agent", "grant_types": []string{"authorization_code", topoGrantTE},
		"response_types": []string{"code"}, "token_endpoint_auth_method": "client_secret_basic",
		"scope": "tool:list tool:create",
	})
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug: "cal-mcp", URI: "https://cal-mcp.brokermcp.test", BackendKind: "mint", DisplayName: "Calendar MCP",
		Scopes: []e2e.AdminScope{{Name: "tool:list"}, {Name: "tool:create"}},
		Policy: &e2e.AdminPolicy{Runtime: e2e.AdminRuntimePolicy{ClientIDs: []string{f.agent}}},
	})
	return f
}

// issuerToken is a token for the confidential agent minted with resource
// omitted (aud = issuer), carrying scopes.
func (f *brokerMCPFixture) issuerToken(t *testing.T, scopes ...string) string {
	t.Helper()
	c := topoLoggedIn(t, f.h, f.email)
	v, ch := topoPKCE()
	code := topoCodeFor(t, f.h, c, topoAuthorizeParams(f.agent, topoRedirect, "", strings.Join(scopes, " "), ch, "S256"), scopes)
	r := topoToken(t, f.h, map[string][]string{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {topoRedirect}, "code_verifier": {v},
	}, topoAuthBasic, f.agent, f.secret)
	if !r.OK() {
		t.Fatalf("precondition: issuer-audienced token: %s", r.Raw)
	}
	return r.AccessToken()
}

// attest records the user's consent to the agent at cal-mcp.
func (f *brokerMCPFixture) attest(t *testing.T, scopes ...string) {
	t.Helper()
	topoCode(t, f.h, f.email, f.agent, "cal-mcp", scopes)
}

func (f *brokerMCPFixture) vends() int { return len(f.h.TokenRequests("google")) }

func TestTopologyBrokerMCP_Adversarial(t *testing.T) {
	t.Parallel()
	// The page: a Broker Resource is never the target of /authorize (refused
	// with 400); the documented first step authorizes the agent at its own
	// Mint resource, which reaches consent.
	t.Run("DocumentedFlow_AuthorizeAtAgentResource", func(t *testing.T) {
		t.Parallel()
		f := newBrokerMCPFixture(t)
		c := topoLoggedIn(t, f.h, f.email)
		_, ch := topoPKCE()
		st, loc := topoAuthorizeRaw(t, f.h, c, topoAuthorizeParams(f.agent, topoRedirect, "cal-mcp", "tool:list", ch, "S256"))
		if !strings.HasPrefix(loc, "/consent") {
			t.Errorf("documented first step /authorize?resource=cal-mcp does not reach consent (status %d, Location %q)", st, loc)
		}
		if st, _ := topoAuthorizeRaw(t, f.h, c, topoAuthorizeParams(f.pubAgent, topoRedirect, "google-cal", "tool:list", ch, "S256")); st != 400 {
			t.Errorf("/authorize?resource=google-cal: status %d, want 400 as the page states", st)
		}
	})

	t.Run("CommonMistake_MintAudiencedSubject_FrontingLinkMissing", func(t *testing.T) {
		t.Parallel()
		f := newBrokerMCPFixture(t)
		f.h.RunFlowConnect(f.email, topoPassword, "google")
		code, v := topoCode(t, f.h, f.email, f.agent, "cal-mcp", []string{"tool:list"})
		tok := topoToken(t, f.h, map[string][]string{
			"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {topoRedirect}, "code_verifier": {v},
		}, topoAuthBasic, f.agent, f.secret)
		r := topoToken(t, f.h, topoExchangeForm(tok.AccessToken(), "google-cal", "tool:list"), topoAuthBasic, f.agent, f.secret)
		desc := r.str("error_description")
		if r.OK() || r.Err() != "invalid_request" || !strings.Contains(desc, "no fronting link declared") {
			t.Errorf("Mint-audienced subject at a broker: status %d error %q desc %q, want the documented invalid_request / fronting_link_missing", r.Status, r.Err(), desc)
		}
		// The description sends the operator to a doc; that doc must exist.
		if m := regexp.MustCompile(`see (docs/\S+\.md)`).FindStringSubmatch(desc); m != nil {
			if _, err := os.Stat(filepath.Join("..", "..", m[1])); err != nil {
				t.Errorf("%s: error_description points operators at %q, which does not exist in the repository (the page lives at docs/topologies/)", topoFindingPrefix, m[1])
			}
		}
		topoExpectAudit(t, f.h, "token.exchange_denied", "reason=fronting_link_missing", func(r topoAuditRow) bool {
			return r.ClientID == f.agent && strings.Contains(r.Detail, "reason=fronting_link_missing")
		})
	})

	t.Run("DirectDispatch_Legitimate_BothAuthMethods", func(t *testing.T) {
		t.Parallel()
		f := newBrokerMCPFixture(t)
		f.h.RunFlowConnect(f.email, topoPassword, "google")
		f.attest(t, "tool:list")
		sub := f.issuerToken(t, "tool:list")
		for _, auth := range topoBothAuth {
			r := topoToken(t, f.h, topoExchangeForm(sub, "google-cal", "tool:list"), auth, f.agent, f.secret)
			if !r.OK() || r.AccessToken() != brokerMCPUpstreamToken {
				t.Fatalf("%s: direct broker dispatch: %d %s", auth, r.Status, r.Raw)
			}
			last := f.h.TokenRequests("google")[f.vends()-1]
			if last.Get("scope") != "calendar.readonly" {
				t.Errorf("%s: upstream asked for %q, want calendar.readonly", auth, last.Get("scope"))
			}
		}
		topoExpectAudit(t, f.h, "token.exchanged", "type=broker_dispatch without chain_kind", func(r topoAuditRow) bool {
			return r.ActorID == f.userID && r.ClientID == f.agent &&
				topoDetailHas(r.Detail, "type=broker_dispatch", "resource=google-cal", "provider=google") && !strings.Contains(r.Detail, "chain_kind=")
		})
	})

	// The fix at this release derives an omitted scope on both *fronted*
	// paths; its commit message records that "direct exchanges are
	// unchanged". On the direct broker path an empty request passes the
	// ceiling, the attestation-coverage check and the broker bounds
	// vacuously, and the adapter refreshes with no scope parameter at all —
	// i.e. the user's full upstream grant.
	t.Run("DirectDispatch_OmittedScope_NeverVendsBeyondAttestation", func(t *testing.T) {
		t.Parallel()
		f := newBrokerMCPFixture(t)
		f.h.RunFlowConnect(f.email, topoPassword, "google") // upstream grant: readonly + events
		f.attest(t, "tool:list")                            // attested for tool:list only
		sub := f.issuerToken(t, "tool:list")
		before := f.vends()
		r := topoToken(t, f.h, topoExchangeForm(sub, "google-cal", ""), topoAuthBasic, f.agent, f.secret)
		if !r.OK() {
			return // refused: conforming
		}
		if f.vends() == before {
			t.Fatal("success without an upstream call")
		}
		last := f.h.TokenRequests("google")[f.vends()-1]
		if _, sent := last["scope"]; !sent || last.Get("scope") != "calendar.readonly" {
			t.Errorf("%s: direct broker exchange with scope omitted vended the user's upstream credential with upstream scope=%q (sent=%v) and response scope=%q; the agent is attested for tool:list (calendar.readonly) only, so calendar.events rides along",
				topoFindingPrefix, last.Get("scope"), sent, r.Scope())
		}
	})

	t.Run("UnderPrivileged_AttestationDoesNotCoverScope", func(t *testing.T) {
		t.Parallel()
		f := newBrokerMCPFixture(t)
		f.h.RunFlowConnect(f.email, topoPassword, "google")
		f.attest(t, "tool:list")
		sub := f.issuerToken(t, "tool:list", "tool:create")
		before := f.vends()
		r := topoToken(t, f.h, topoExchangeForm(sub, "google-cal", "tool:create"), topoAuthBasic, f.agent, f.secret)
		if r.OK() || r.Err() != "consent_required" {
			t.Errorf("tool:create beyond attestation: status %d error %q, want consent_required", r.Status, r.Err())
		}
		if !strings.Contains(r.str("consent_url"), "resource=cal-mcp") {
			t.Errorf("consent_url %q should send the user back to re-consent at cal-mcp", r.str("consent_url"))
		}
		if f.vends() != before {
			t.Error("refused exchange reached the upstream")
		}
		topoExpectAudit(t, f.h, "token.exchange_denied", "reason=broker_scope_not_consented", func(r topoAuditRow) bool {
			return r.ClientID == f.agent && strings.Contains(r.Detail, "reason=broker_scope_not_consented")
		})
	})

	t.Run("ForeignActor_NotBoundToAnyMCP", func(t *testing.T) {
		t.Parallel()
		f := newBrokerMCPFixture(t)
		f.h.RunFlowConnect(f.email, topoPassword, "google")
		f.attest(t, "tool:list")
		sub := f.issuerToken(t, "tool:list")
		foreign, foreignSecret := topoCreateClient(t, f.h, map[string]any{
			"client_name": "unbound", "grant_types": []string{topoGrantTE},
			"token_endpoint_auth_method": "client_secret_basic", "scope": "tool:list",
		})
		for _, auth := range topoBothAuth {
			for _, scope := range []string{"tool:list", ""} {
				if r := topoToken(t, f.h, topoExchangeForm(sub, "google-cal", scope), auth, foreign, foreignSecret); r.OK() {
					t.Errorf("%s: unbound client vended the user's upstream token (scope %q)", auth, scope)
				} else if r.Err() != "access_denied" {
					t.Errorf("%s: unbound client (scope %q): error %q, want access_denied", auth, scope, r.Err())
				}
			}
		}
		topoExpectAudit(t, f.h, "token.exchange_denied", "reason=agent_attestation_unknown_actor", func(r topoAuditRow) bool {
			return r.ClientID == foreign && strings.Contains(r.Detail, "reason=agent_attestation_unknown_actor")
		})
	})

	t.Run("NotConnected_ConsentRequiredWithConnectURL", func(t *testing.T) {
		t.Parallel()
		f := newBrokerMCPFixture(t)
		f.attest(t, "tool:list")
		r := topoToken(t, f.h, topoExchangeForm(f.issuerToken(t, "tool:list"), "google-cal", "tool:list"), topoAuthBasic, f.agent, f.secret)
		if r.OK() || r.Err() != "consent_required" {
			t.Fatalf("not connected: status %d error %q", r.Status, r.Err())
		}
		if cu := r.str("consent_url"); !strings.HasPrefix(cu, f.h.Issuer+"/connect/google") {
			t.Errorf("consent_url = %q, want %s/connect/google…", cu, f.h.Issuer)
		}
	})

	t.Run("RevocationReach_BrokerGrantAndAttestation", func(t *testing.T) {
		t.Parallel()
		f := newBrokerMCPFixture(t)
		f.h.RunFlowConnect(f.email, topoPassword, "google")
		f.attest(t, "tool:list")
		sub := f.issuerToken(t, "tool:list")
		exch := func() topoResp {
			return topoToken(t, f.h, topoExchangeForm(sub, "google-cal", "tool:list"), topoAuthBasic, f.agent, f.secret)
		}
		if r := exch(); !r.OK() {
			t.Fatalf("precondition: %s", r.Raw)
		}
		topoRevokeConsent(t, f.h, topoConsentGrantID(t, f.h, f.userID, f.agent, "cal-mcp"))
		if r := exch(); r.OK() || r.Err() != "consent_required" {
			t.Errorf("after attestation revoked: status %d error %q, want consent_required", r.Status, r.Err())
		}
		f.attest(t, "tool:list")
		grants := listUserGrants(t, f.h, f.userID).BrokerGrants
		if len(grants) != 1 {
			t.Fatalf("broker grants = %d", len(grants))
		}
		resp := f.h.AdminRequest(http.MethodDelete, "/admin/grants/broker/"+grants[0].ID, nil)
		resp.Body.Close()
		if r := exch(); r.OK() || r.Err() != "consent_required" {
			t.Errorf("after broker grant revoked: status %d error %q, want consent_required", r.Status, r.Err())
		}
		topoExpectAudit(t, f.h, "broker_grant.revoked_admin", "for the grant", func(r topoAuditRow) bool {
			return strings.Contains(r.Detail, "id="+grants[0].ID)
		})
	})

	t.Run("RevocationReach_DisabledUser", func(t *testing.T) {
		t.Parallel()
		f := newBrokerMCPFixture(t)
		f.h.RunFlowConnect(f.email, topoPassword, "google")
		f.attest(t, "tool:list")
		sub := f.issuerToken(t, "tool:list")
		f.h.DisableUser(f.userID)
		if r := topoToken(t, f.h, topoExchangeForm(sub, "google-cal", "tool:list"), topoAuthBasic, f.agent, f.secret); r.OK() {
			t.Errorf("%s: a disabled user's upstream credential was vended (%q)", topoFindingPrefix, r.AccessToken())
		}
	})
}
