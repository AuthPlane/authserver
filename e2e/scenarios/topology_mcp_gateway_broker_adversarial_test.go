//go:build e2e

package scenarios

import (
	"net/http"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// Topology: mcp-gateway-broker (docs/topologies/mcp-gateway-broker.md).
//
// Configured as the page's REST walkthrough: provider google (the harness's
// in-process mock upstream), Mint mcp-gw (tool:list, tool:create), Broker
// google-cal (tool:list → calendar.readonly, tool:create → calendar.events),
// fronting link mcp-gw → google-cal mapping each scope to itself, and the
// gateway as a confidential [client_credentials, token-exchange] client with
// client_secret_basic. No allowed_client_ids, as on the page.
//
// The page promises: the gateway gets the upstream bearer (never an AS JWT),
// the upstream is asked only for what the subject's source scope maps to,
// consent_required with a /connect/google consent_url when the user has not
// connected, and a token.exchanged row carrying type=broker_dispatch
// chain_kind=fronted target_kind=broker via_link=mcp-gw->google-cal.

const gwBrokerUpstreamToken = "goog_gwbroker_upstream_token"

type gwBrokerFixture struct {
	h             *e2e.TestHarness
	agent         string
	gw, gwSecret  string
	userID, email string
}

func newGWBrokerFixture(t *testing.T) *gwBrokerFixture {
	t.Helper()
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI: true, EnableTokenExchange: true, EnableClientCredentials: true, TokenExchangeMaxChainDepth: 5,
		Connectors: []e2e.ConnectorConfig{{
			Service: "google", Scopes: []string{"calendar.readonly", "calendar.events"},
			AccessToken: gwBrokerUpstreamToken, RefreshToken: gwBrokerUpstreamToken, ExpiresIn: 3600,
		}},
	}, []string{"placeholder"})
	f := &gwBrokerFixture{h: h, email: "gwbroker-alice@example.com"}
	f.userID = h.CreateUser(f.email, topoPassword)
	mock := h.MockUpstreamURL("google")
	h.AdminCreateBrokerProvider(e2e.CreateBrokerProviderSpec{
		Slug: "google", DisplayName: "Google", Protocol: "oauth",
		ConfigData: map[string]any{
			"client_id": "mock-google-client", "client_secret_ref": "CONNECTOR_GOOGLE_SECRET",
			"authorize_url": mock + "/authorize", "token_url": mock + "/token",
			"extra_auth_params": map[string]string{"access_type": "offline", "prompt": "consent"},
		},
	})
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug: "mcp-gw", URI: "https://mcp-gw.gwbroker.test", BackendKind: "mint", DisplayName: "MCP Gateway",
		Scopes: []e2e.AdminScope{{Name: "tool:list"}, {Name: "tool:create"}},
	})
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug: "google-cal", URI: "https://google-cal.broker.test", BackendKind: "broker",
		BrokerProviderSlug: "google", DisplayName: "Google Calendar",
		Scopes: []e2e.AdminScope{
			{Name: "tool:list", Upstream: "calendar.readonly"},
			{Name: "tool:create", Upstream: "calendar.events"},
		},
	})
	h.AdminCreateFrontingLink(e2e.CreateFrontingLinkSpec{
		Source: "mcp-gw", Target: "google-cal",
		ScopeMap: map[string][]string{"tool:list": {"tool:list"}, "tool:create": {"tool:create"}},
	})
	f.gw, f.gwSecret = topoCreateClient(t, h, map[string]any{
		"client_name": "mcp-gw", "grant_types": []string{"client_credentials", topoGrantTE},
		"token_endpoint_auth_method": "client_secret_basic", "scope": "tool:list tool:create",
	})
	f.agent = h.AdminCreatePublicClient("my-agent", []string{"authorization_code"}, "tool:list tool:create", []string{topoRedirect})
	// The gateway declares itself as mcp-gw's runtime client — the step that
	// lets it, and only it, drive exchanges through the fronting link.
	h.AdminAddRuntimeClientID("mcp-gw", f.gw)
	return f
}

func (f *gwBrokerFixture) gwToken(t *testing.T, scopes ...string) string {
	t.Helper()
	return topoUserToken(t, f.h, f.email, f.agent, "mcp-gw", scopes).AccessToken()
}

func (f *gwBrokerFixture) exchange(t *testing.T, auth topoAuth, subject, scope string) topoResp {
	t.Helper()
	return topoToken(t, f.h, topoExchangeForm(subject, "google-cal", scope), auth, f.gw, f.gwSecret)
}

// lastUpstreamScope is the scope the AS sent to the upstream on its most
// recent vend, and whether it sent one.
func (f *gwBrokerFixture) lastUpstreamScope(t *testing.T) (string, bool) {
	t.Helper()
	reqs := f.h.TokenRequests("google")
	if len(reqs) == 0 {
		t.Fatal("upstream token endpoint never called")
	}
	last := reqs[len(reqs)-1]
	_, sent := last["scope"]
	return last.Get("scope"), sent
}

func TestTopologyMCPGatewayBroker_Adversarial(t *testing.T) {
	t.Parallel()
	t.Run("LegitimateFlow_UpstreamBearerAndAudit", func(t *testing.T) {
		t.Parallel()
		f := newGWBrokerFixture(t)
		f.h.RunFlowConnect(f.email, topoPassword, "google")
		sub := f.gwToken(t, "tool:list")
		for _, auth := range topoBothAuth {
			r := f.exchange(t, auth, sub, "tool:list")
			if !r.OK() {
				t.Fatalf("%s: exchange: %d %s", auth, r.Status, r.Raw)
			}
			if r.AccessToken() != gwBrokerUpstreamToken || r.str("token_type") != "Bearer" {
				t.Errorf("%s: got %q/%q, want the upstream bearer", auth, r.AccessToken(), r.str("token_type"))
			}
			if s, _ := f.lastUpstreamScope(t); s != "calendar.readonly" {
				t.Errorf("%s: upstream asked for %q, want calendar.readonly", auth, s)
			}
		}
		topoExpectAudit(t, f.h, "token.exchanged", "fronted broker dispatch", func(r topoAuditRow) bool {
			return r.ActorID == f.userID && topoDetailHas(r.Detail, "type=broker_dispatch", "chain_kind=fronted",
				"target_kind=broker", "via_link=mcp-gw->google-cal", "subject_client="+f.agent)
		})
	})

	t.Run("NotConnected_ConsentRequiredWithConnectURL", func(t *testing.T) {
		t.Parallel()
		f := newGWBrokerFixture(t)
		r := f.exchange(t, topoAuthBasic, f.gwToken(t, "tool:list"), "tool:list")
		if r.OK() || r.Err() != "consent_required" {
			t.Fatalf("not connected: status %d error %q, want consent_required", r.Status, r.Err())
		}
		if cu := r.str("consent_url"); !strings.HasPrefix(cu, f.h.Issuer+"/connect/google") {
			t.Errorf("consent_url = %q, want prefix %s/connect/google", cu, f.h.Issuer)
		}
		topoExpectAudit(t, f.h, "token.exchange_denied", "denied_reason=upstream_connection_missing", func(r topoAuditRow) bool {
			return topoDetailHas(r.Detail, "chain_kind=fronted", "denied_reason=upstream_connection_missing")
		})
	})

	t.Run("OmittedScope_UpstreamAskedOnlyForMappedScope", func(t *testing.T) {
		t.Parallel()
		f := newGWBrokerFixture(t)
		f.h.RunFlowConnect(f.email, topoPassword, "google")
		r := f.exchange(t, topoAuthBasic, f.gwToken(t, "tool:list"), "")
		if !r.OK() {
			t.Fatalf("scope omitted: %d %s", r.Status, r.Raw)
		}
		s, sent := f.lastUpstreamScope(t)
		if !sent || s != "calendar.readonly" {
			t.Errorf("scope omitted: upstream vend scope = %q (sent=%v), want calendar.readonly — never the full grant", s, sent)
		}
		topoAssertScopeWithin(t, "response scope", r.Scope(), true, "tool:list")
	})

	t.Run("OmittedResource_NoVend", func(t *testing.T) {
		t.Parallel()
		f := newGWBrokerFixture(t)
		f.h.RunFlowConnect(f.email, topoPassword, "google")
		before := len(f.h.TokenRequests("google"))
		r := topoToken(t, f.h, topoExchangeForm(f.gwToken(t, "tool:list"), "", "tool:list"), topoAuthBasic, f.gw, f.gwSecret)
		if r.AccessToken() == gwBrokerUpstreamToken {
			t.Error("resource omitted vended the upstream bearer")
		}
		if after := len(f.h.TokenRequests("google")); after != before {
			t.Errorf("resource omitted still called the upstream (%d → %d)", before, after)
		}
	})

	t.Run("UnderPrivilegedSubject_NoVend", func(t *testing.T) {
		t.Parallel()
		f := newGWBrokerFixture(t)
		f.h.RunFlowConnect(f.email, topoPassword, "google")
		sub := f.gwToken(t, "tool:list")
		before := len(f.h.TokenRequests("google"))
		for _, scope := range []string{"tool:create", "tool:list tool:create"} {
			r := f.exchange(t, topoAuthBasic, sub, scope)
			if r.OK() {
				t.Errorf("subject with tool:list only vended %q", scope)
			} else if r.Err() != "consent_required" {
				t.Errorf("scope %q: error %q, want consent_required", scope, r.Err())
			}
		}
		if after := len(f.h.TokenRequests("google")); after != before {
			t.Errorf("refused exchanges still reached the upstream (%d → %d)", before, after)
		}
		topoExpectAudit(t, f.h, "token.exchange_denied", "denied_reason=subject_scope_insufficient", func(r topoAuditRow) bool {
			return topoDetailHas(r.Detail, "chain_kind=fronted", "target_kind=broker", "denied_reason=subject_scope_insufficient")
		})
	})

	t.Run("ActorToken_RejectedForBroker", func(t *testing.T) {
		t.Parallel()
		f := newGWBrokerFixture(t)
		f.h.RunFlowConnect(f.email, topoPassword, "google")
		sub := f.gwToken(t, "tool:list")
		form := topoExchangeForm(sub, "google-cal", "tool:list")
		form.Set("actor_token", sub)
		form.Set("actor_token_type", topoTokenTypeAT)
		if r := topoToken(t, f.h, form, topoAuthBasic, f.gw, f.gwSecret); r.OK() || r.Err() != "invalid_request" {
			t.Errorf("actor_token on a broker target: status %d error %q, want invalid_request", r.Status, r.Err())
		}
	})

	t.Run("ForeignAgent_DCRWithTokenExchange_CannotVendUsersUpstreamToken", func(t *testing.T) {
		t.Parallel()
		f := newGWBrokerFixture(t)
		f.h.RunFlowConnect(f.email, topoPassword, "google")
		rogue, rogueSecret := topoDCR(t, f.h, map[string]any{
			"client_name": "calendar-helper", "grant_types": []string{"authorization_code", topoGrantTE},
			"response_types": []string{"code"}, "token_endpoint_auth_method": "client_secret_post",
		})
		code, v := topoCode(t, f.h, f.email, rogue, "mcp-gw", []string{"tool:list"})
		own := topoToken(t, f.h, map[string][]string{
			"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {topoRedirect}, "code_verifier": {v},
		}, topoAuthPost, rogue, rogueSecret)
		if !own.OK() {
			t.Fatalf("precondition: rogue's mcp-gw token: %s", own.Raw)
		}
		r := topoToken(t, f.h, topoExchangeForm(own.AccessToken(), "google-cal", ""), topoAuthPost, rogue, rogueSecret)
		if r.OK() {
			t.Errorf("%s: a DCR-registered client that is not the gateway received the user's upstream Google bearer (%q) by exchanging its own mcp-gw token",
				topoFindingPrefix, r.AccessToken())
		}
	})

	// The page: the act chain "lives only in the AS audit log". The client
	// that actually called /oauth/token is the one part of that chain the AS
	// authenticated; the success row must name it.
	t.Run("Audit_SuccessRowNamesTheCallingClient", func(t *testing.T) {
		t.Parallel()
		f := newGWBrokerFixture(t)
		f.h.RunFlowConnect(f.email, topoPassword, "google")
		if r := f.exchange(t, topoAuthBasic, f.gwToken(t, "tool:list"), "tool:list"); !r.OK() {
			t.Fatalf("exchange: %s", r.Raw)
		}
		found := false
		for _, row := range topoAudit(t, f.h, "token.exchanged") {
			if !strings.Contains(row.Detail, "type=broker_dispatch") {
				continue
			}
			if row.ClientID == f.gw || strings.Contains(row.Detail, f.gw) {
				found = true
			} else {
				t.Logf("fronted broker success row: actor_id=%q client_id=%q detail=%q", row.ActorID, row.ClientID, row.Detail)
			}
		}
		if !found {
			t.Errorf("%s: no token.exchanged row names the authenticated caller %q; client_id and actor_client both carry the source slug, so who vended the upstream bearer is not recorded",
				topoFindingPrefix, f.gw)
		}
	})

	t.Run("RevocationReach_BrokerGrant", func(t *testing.T) {
		t.Parallel()
		f := newGWBrokerFixture(t)
		f.h.RunFlowConnect(f.email, topoPassword, "google")
		sub := f.gwToken(t, "tool:list")
		if r := f.exchange(t, topoAuthBasic, sub, "tool:list"); !r.OK() {
			t.Fatalf("precondition: %s", r.Raw)
		}
		grants := listUserGrants(t, f.h, f.userID).BrokerGrants
		if len(grants) != 1 {
			t.Fatalf("broker grants = %d, want 1", len(grants))
		}
		resp := f.h.AdminRequest(http.MethodDelete, "/admin/grants/broker/"+grants[0].ID, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("DELETE broker grant: %d", resp.StatusCode)
		}
		if r := f.exchange(t, topoAuthBasic, sub, "tool:list"); r.OK() || r.Err() != "consent_required" {
			t.Errorf("after broker-grant revocation: status %d error %q, want consent_required", r.Status, r.Err())
		}
		topoExpectAudit(t, f.h, "broker_grant.revoked_admin", "for the grant", func(r topoAuditRow) bool {
			return strings.Contains(r.Detail, "id="+grants[0].ID)
		})
	})

	t.Run("RevocationReach_SourceConsent", func(t *testing.T) {
		t.Parallel()
		f := newGWBrokerFixture(t)
		f.h.RunFlowConnect(f.email, topoPassword, "google")
		sub := f.gwToken(t, "tool:list")
		topoRevokeConsent(t, f.h, topoConsentGrantID(t, f.h, f.userID, f.agent, "mcp-gw"))
		if r := f.exchange(t, topoAuthBasic, sub, "tool:list"); r.OK() || r.Err() != "invalid_grant" {
			t.Errorf("revoked source token: status %d error %q, want invalid_grant", r.Status, r.Err())
		}
	})

	t.Run("RevocationReach_DisabledUser", func(t *testing.T) {
		t.Parallel()
		f := newGWBrokerFixture(t)
		f.h.RunFlowConnect(f.email, topoPassword, "google")
		sub := f.gwToken(t, "tool:list")
		f.h.DisableUser(f.userID)
		if r := f.exchange(t, topoAuthBasic, sub, "tool:list"); r.OK() {
			t.Errorf("%s: a disabled user's stored Google credential was vended to the gateway (%q)", topoFindingPrefix, r.AccessToken())
		}
	})
}
