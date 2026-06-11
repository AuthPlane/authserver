//go:build e2e

package scenarios

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/e2e"
)

// admin_grants_test.go covers the GET /admin/users/{id}/grants and
// DELETE /admin/grants/{consent,broker}/{id} surfaces end-to-end. It
// replaces the Gate-0 shortcuts in api/admin/handlers_test.go
// (TestAdmin_UserGrants_*, TestAdmin_BrokerGrantViews_*,
// TestAdmin_RevokeConsentGrant_*, TestAdmin_RevokeBrokerGrant_*) where
// each test seeded the consent_grants / broker_grants / issuances
// tables directly via the store.  (closes ).
//
// Pattern:
//   - Drive consent_grants creation via h.RunFlowC1Consent (the public
//     /authorize + /consent dance — same code path  wires).
//   - Drive broker_grants creation via h.RunFlowConnect (the public
//     /connect/{provider} dance — same code path  wires).
//   - Drive issuance creation via h.TokenExchangeWithResource (the
//     public /oauth/token RFC 8693 path — MintIssuer.Issue persists
//     the issuances row).
//   - Read back through GET /admin/users/{id}/grants and
//     GET /admin/issuances?... — the same operator-facing endpoints
//     the admin UI uses.

// adminUserGrantsList is the local mirror of dto.UserGrantsView. The
// inner ConsentGrantView is reused from ap306_three_bound_test.go
// (adminConsentGrantView) — the same package, no duplication needed.
// adminBrokerGrantViewLocal is unique to this file because no other
// scenario reads broker_grants over the admin wire yet.
type adminUserGrantsListResp struct {
	ConsentGrants []adminConsentGrantView     `json:"consent_grants"`
	BrokerGrants  []adminBrokerGrantViewLocal `json:"broker_grants"`
}

// adminBrokerGrantViewLocal mirrors the subset of dto.BrokerGrantView
// the migrated tests read. CredentialData is intentionally omitted —
// the view types must not expose it ( security guard, defended
// in TestAdmin_BrokerGrantViews_NeverLeakCredentialData below).
type adminBrokerGrantViewLocal struct {
	ID               string   `json:"id"`
	UserID           string   `json:"user_id"`
	BrokerProviderID string   `json:"broker_provider_id"`
	ScopesGranted    []string `json:"scopes_granted"`
}

// listUserGrants performs GET /admin/users/{id}/grants and decodes
// the response. Fails the test on non-200.
func listUserGrants(t *testing.T, h *e2e.TestHarness, userID string) adminUserGrantsListResp {
	t.Helper()
	resp := h.AdminRequest("GET", "/admin/users/"+userID+"/grants", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /admin/users/%s/grants: status %d, body %s", userID, resp.StatusCode, raw)
	}
	var out adminUserGrantsListResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode user grants: %v", err)
	}
	return out
}

// TestAdmin_UserGrants_AuthRequired pins the auth gate on
// GET /admin/users/{id}/grants. Replaces the same-named test in
// api/admin/handlers_test.go.
func TestAdmin_UserGrants_AuthRequired(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI: true,
	}, []string{"tools/echo"})

	resp, err := http.Get(h.AdminAPI.URL + "/admin/users/alice/grants")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", resp.StatusCode)
	}
}

// TestAdmin_UserGrants_ListReturnsBothShapes verifies that
// GET /admin/users/{id}/grants returns both consent_grants and
// broker_grants for a user that has authorised an agent at one MCP and
// connected to one upstream provider. Replaces the seedConsentGrant +
// seedBrokerGrant variant of the original test.
func TestAdmin_UserGrants_ListReturnsBothShapes(t *testing.T) {
	// client_ids are auto-generated; mcpSlug stays operator-meaningful.
	const (
		mcpSlug      = "ug-bothshapes-mcp"
		providerSlug = "ug-bothshapes-bp"
		email        = "alice-ugboth@example.com"
		password     = "pass123"
	)

	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI: true,
		Connectors: []e2e.ConnectorConfig{
			{
				Service:      providerSlug,
				Scopes:       []string{"calendar"},
				AccessToken:  "mock-broker-access-token",
				RefreshToken: "mock-broker-refresh-token",
				ExpiresIn:    3600,
			},
		},
	}, scopes)

	rs := servers[0]
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	userID := h.CreateUser(email, password)

	webAppClientID := h.AdminCreatePublicClient("ug-bothshapes-webapp", []string{"authorization_code"}, "tools/echo", nil)

	// Mint resource for the actor MCP (slug == mcpSlug).
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:        mcpSlug,
		URI:         "https://" + mcpSlug + ".test",
		BackendKind: "mint",
		DisplayName: "MCP " + mcpSlug,
		Scopes: []e2e.AdminScope{
			{Name: "tools/echo"},
		},
	})

	// Drive the per-MCP consent flow → produces a consent_grants row for
	// (userID, webAppClientID, mcpSlug-resource).
	h.RunFlowC1Consent(
		email, password, webAppClientID, "http://localhost:9999/callback",
		mcpSlug,
		[]string{"tools/echo"}, []string{"tools/echo"},
	)

	// Broker provider + Broker resource so RunFlowConnect can run.
	mockBase := h.MockUpstreamURL(providerSlug)
	h.AdminCreateBrokerProvider(e2e.CreateBrokerProviderSpec{
		Slug:        providerSlug,
		DisplayName: providerSlug,
		Protocol:    "oauth",
		ConfigData: map[string]any{
			"client_id":         "mock-client-id",
			"client_secret_env": "CONNECTOR_E2E_MOCK_SECRET",
			"authorize_url":     mockBase + "/authorize",
			"token_url":         mockBase + "/token",
			"response_format":   "standard",
		},
	})
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:               providerSlug,
		URI:                "https://" + providerSlug + ".test",
		BackendKind:        "broker",
		BrokerProviderSlug: providerSlug,
		DisplayName:        providerSlug,
		Scopes: []e2e.AdminScope{
			{Name: "calendar", Upstream: "calendar"},
		},
	})

	// Drive the /connect dance → produces a broker_grants row for
	// (userID, providerSlug).
	h.RunFlowConnect(email, password, providerSlug)

	// Resolve the actor-MCP resource id and broker provider id so we can
	// match the rows that the public flow produced — the AS allocates
	// UUIDs server-side.
	mcpRes := h.AdminGetResourceBySlug(mcpSlug)
	bp := h.AdminGetBrokerProviderBySlug(providerSlug)

	got := listUserGrants(t, h, userID)

	if len(got.ConsentGrants) != 1 {
		t.Errorf("consent_grants: got %d rows, want 1", len(got.ConsentGrants))
	} else {
		cg := got.ConsentGrants[0]
		if cg.UserID != userID {
			t.Errorf("consent_grants[0].user_id: got %q, want %q", cg.UserID, userID)
		}
		if cg.ClientID != webAppClientID {
			t.Errorf("consent_grants[0].client_id: got %q, want %q", cg.ClientID, webAppClientID)
		}
		if cg.ResourceID != mcpRes.ID {
			t.Errorf("consent_grants[0].resource_id: got %q, want %q", cg.ResourceID, mcpRes.ID)
		}
	}

	if len(got.BrokerGrants) != 1 {
		t.Errorf("broker_grants: got %d rows, want 1", len(got.BrokerGrants))
	} else {
		bg := got.BrokerGrants[0]
		if bg.UserID != userID {
			t.Errorf("broker_grants[0].user_id: got %q, want %q", bg.UserID, userID)
		}
		if bg.BrokerProviderID != bp.ID {
			t.Errorf("broker_grants[0].broker_provider_id: got %q, want %q", bg.BrokerProviderID, bp.ID)
		}
	}
}

// TestAdmin_BrokerGrantViews_NeverLeakCredentialData is the load-bearing
// regression test for 's primary security guard: the encrypted
// upstream credential MUST NEVER appear in any admin response. The
// pre- version seeded broker_grants directly via
// brokerGrantStore.Create with a literal "encrypted-secret-blob"
// payload; this version goes through the public /connect dance (which
// encrypts the upstream token via the brokerproto/oauth adapter into
// an opaque blob the test never names directly).
func TestAdmin_BrokerGrantViews_NeverLeakCredentialData(t *testing.T) {
	const (
		providerSlug = "bgv-noleak-bp"
		email        = "alice-bgvnoleak@example.com"
		password     = "pass123"
	)

	scopes := []string{"tools/echo"}
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI: true,
		Connectors: []e2e.ConnectorConfig{
			{
				Service:      providerSlug,
				Scopes:       []string{"scope1"},
				AccessToken:  "mock-broker-access-token",
				RefreshToken: "mock-broker-refresh-token",
				ExpiresIn:    3600,
			},
		},
	}, scopes)

	userID := h.CreateUser(email, password)

	mockBase := h.MockUpstreamURL(providerSlug)
	h.AdminCreateBrokerProvider(e2e.CreateBrokerProviderSpec{
		Slug:        providerSlug,
		DisplayName: providerSlug,
		Protocol:    "oauth",
		ConfigData: map[string]any{
			"client_id":         "mock-client-id",
			"client_secret_env": "CONNECTOR_E2E_MOCK_SECRET",
			"authorize_url":     mockBase + "/authorize",
			"token_url":         mockBase + "/token",
			"response_format":   "standard",
		},
	})
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:               providerSlug,
		URI:                "https://" + providerSlug + ".test",
		BackendKind:        "broker",
		BrokerProviderSlug: providerSlug,
		DisplayName:        providerSlug,
		Scopes: []e2e.AdminScope{
			{Name: "scope1", Upstream: "scope1"},
		},
	})
	h.RunFlowConnect(email, password, providerSlug)

	// Resolve the broker grant id via the list endpoint.
	got := listUserGrants(t, h, userID)
	if len(got.BrokerGrants) != 1 {
		t.Fatalf("expected one broker grant in list, got %d", len(got.BrokerGrants))
	}
	bgID := got.BrokerGrants[0].ID

	// 1. List path: GET /admin/users/{id}/grants — must not contain the
	// credential_data key anywhere.
	listResp := h.AdminRequest("GET", "/admin/users/"+userID+"/grants", nil)
	listBody, _ := io.ReadAll(listResp.Body)
	listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list status: %d", listResp.StatusCode)
	}
	if bytes.Contains(listBody, []byte("\"credential_data\"")) {
		t.Fatalf("CRITICAL: credential_data key surfaced in list response: %s", listBody)
	}
	// Sanity: still has a broker_grants entry (defends against the
	// "all stripped → vacuous pass" failure mode).
	var probe adminUserGrantsListResp
	if err := json.Unmarshal(listBody, &probe); err != nil {
		t.Fatalf("decode list body: %v", err)
	}
	if len(probe.BrokerGrants) != 1 {
		t.Fatalf("decoded list expected 1 broker_grant, got %d", len(probe.BrokerGrants))
	}

	// 2. Revoke path: DELETE /admin/grants/broker/{id} (currently 204
	//    no-body, but assert the body, if any, doesn't smuggle the field).
	revResp := h.AdminRequest("DELETE", "/admin/grants/broker/"+bgID, nil)
	revBody, _ := io.ReadAll(revResp.Body)
	revResp.Body.Close()
	if revResp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke status: got %d, want 204: %s", revResp.StatusCode, revBody)
	}
	if bytes.Contains(revBody, []byte("credential_data")) {
		t.Fatalf("CRITICAL: credential_data appeared in revoke response: %s", revBody)
	}

	// 3. Post-revoke list still must not leak the field even though
	//    the row now has revoked_at set.
	listResp2 := h.AdminRequest("GET", "/admin/users/"+userID+"/grants", nil)
	listBody2, _ := io.ReadAll(listResp2.Body)
	listResp2.Body.Close()
	if bytes.Contains(listBody2, []byte("credential_data")) {
		t.Fatalf("CRITICAL: credential_data leaked in post-revoke list: %s", listBody2)
	}
	if bytes.Contains(listBody2, []byte("\"credential_data\"")) {
		t.Fatalf("CRITICAL: credential_data JSON key surfaced anywhere")
	}
}

// TestAdmin_RevokeConsentGrant_CascadeRevokesIssuances verifies that
// DELETE /admin/grants/consent/{id} cascades revoked_at onto every
// issuance row keyed on the same (user, client, resource) tuple. The
// pre- version directly inserted both rows via the store with a
// shared client_id; this version drives a Mint token-exchange to
// produce the issuance.
//
// Cascade keying: GrantAdminService.RevokeConsent reads (UserID,
// ClientID, ResourceID) from the consent_grants row and calls
// IssuanceStore.RevokeFamily on the same triple. The consent_grants
// row's ClientID is the agent the user authorised at /authorize; the
// issuance row's ClientID is the actor doing the token exchange. For
// the cascade to fire the two must match — i.e., the user must have
// authorised the actor MCP AT the actor MCP. The original test arranged
// this via shared seed `cID`; here we drive both flows with a single
// confidential client (both authorization_code + token-exchange grants)
// that acts as agent and actor in turn.
func TestAdmin_RevokeConsentGrant_CascadeRevokesIssuances(t *testing.T) {
	const (
		mcpSlug  = "rcg-cascade-actor"
		email    = "alice-rcgcascade@example.com"
		password = "pass123"
	)

	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI:             true,
		EnableTokenExchange:        true,
		TokenExchangeMaxChainDepth: 5,
	}, scopes)

	rs := servers[0]
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")
	userID := h.CreateUser(email, password)

	// Single confidential client wearing both hats: it drives the
	// auth-code flow (so the user's token carries client_id=clientID,
	// matching the consent_grants row), then it calls /oauth/token
	// for the token exchange (so issuance.ClientID=clientID, satisfying
	// RevokeFamily's lookup). client_id auto-generated; the
	// actor-MCP Mint Resource binds it via runtime.client_ids.
	clientID, clientSecret := h.AdminCreateConfidentialClient(
		"rcg-cascade actor",
		[]string{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"},
		"tools/echo",
	)

	// Actor-MCP Mint resource. dispatchMint resolves by the
	// req.Resource parameter.
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:        mcpSlug,
		URI:         "https://" + mcpSlug + ".test",
		BackendKind: "mint",
		DisplayName: "mcp:" + mcpSlug,
		Scopes: []e2e.AdminScope{
			{Name: "tools/echo"},
		},
		Policy: &e2e.AdminPolicy{
			Runtime: e2e.AdminRuntimePolicy{ClientIDs: []string{clientID}},
		},
	})

	// Consent grant for (user, clientID, actor-MCP-resource).
	h.RunFlowC1Consent(
		email, password, clientID, "http://localhost:9999/callback",
		mcpSlug,
		[]string{"tools/echo"}, []string{"tools/echo"},
	)

	// Drive an auth-code flow against rs (mcp-0) so the user gets a
	// token whose client_id == clientID and sub == userID. mcpClient
	// .FullFlow's PKCE-only code exchange does not POST client_secret;
	// for a confidential client we drive the steps individually and
	// POST the form to /oauth/token by hand.
	userTokens := authCodeFlowConfidential(t, h, rs, email, password, clientID, clientSecret, "tools/echo")

	exch := h.TokenExchangeWithResource(
		clientID, clientSecret,
		userTokens.AccessToken, tokenTypeAccessToken,
		"tools/echo",
		mcpSlug,
	)
	if exch.AccessToken == "" {
		t.Fatal("expected exchanged access token")
	}

	// Resolve the consent grant id for the actor-MCP resource. The
	// auth-code flow above produced TWO consent grants — one for the
	// rs's mcp-0 resource (the auth-code helper's own consent dance) and
	// one for the actor MCP resource (RunFlowC1Consent above). Find
	// the actor-MCP one explicitly via the (clientID, mcpRes.ID) tuple.
	mcpRes := h.AdminGetResourceBySlug(mcpSlug)
	cg := findActorConsentGrant(t, h, userID, clientID, mcpRes.ID)
	if cg == nil {
		t.Fatalf("did not find consent grant for actor MCP resource %q", mcpRes.ID)
	}
	cgID := cg.ID

	// Find the Mint issuance against the actor-MCP resource. Only the
	// token-exchange path emits issuances (mint_issuer.Issue inserts
	// only when req.Resource is set), so there should be exactly one.
	issList := listIssuancesByQuery(t, h, "user="+userID)
	var iss *adminIssuanceFullView
	for i := range issList {
		if issList[i].ResourceID == mcpRes.ID {
			iss = &issList[i]
			break
		}
	}
	if iss == nil {
		t.Fatalf("expected an issuance against actor MCP resource, got %d total rows", len(issList))
	}
	if iss.RevokedAt != nil {
		t.Fatalf("pre-revoke: expected live issuance, got revoked_at=%v", iss.RevokedAt)
	}

	revResp := h.AdminRequest("DELETE", "/admin/grants/consent/"+cgID, nil)
	revResp.Body.Close()
	if revResp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke status: %d", revResp.StatusCode)
	}

	// Post-revoke: GET /admin/issuances/{id} carries a revoked_at.
	post := getIssuanceByID(t, h, iss.ID)
	if post.RevokedAt == nil {
		t.Errorf("expected cascaded revoked_at on issuance %s", iss.ID)
	}
}

// authCodeFlowConfidential drives a confidential-client authorization-
// code-with-PKCE flow against the harness's public AS and returns the
// vended user token. Replicates the steps mcpClient.FullFlow takes but
// POSTs client_secret on the /oauth/token call so a confidential
// client's secret check passes (FullFlow uses h.ExchangeCode which
// omits the secret — fine for public clients only).
//
// Lives here next to TestAdmin_RevokeConsentGrant_CascadeRevokesIssuances
// because it's the only test in this file that needs a confidential-
// client auth-code flow. If a future scenario needs the same shape,
// promote it to e2e/harness.go as ExchangeCodeWithSecret.
func authCodeFlowConfidential(t *testing.T, h *e2e.TestHarness, rs *e2e.MCPResourceServer, email, password, clientID, clientSecret, scope string) *e2e.TokenResponse {
	t.Helper()
	mcpClient := e2e.NewMCPClient(t, h, rs, clientID, "http://localhost:9999/callback")
	verifier, challenge := mcpClient.GeneratePKCE()
	params := mcpClient.BuildAuthorizeParams(scope, rs.URI, challenge, "auth-code-conf-state")
	httpClient := h.NewClient()
	res := h.Authorize(httpClient, params)
	if res.NeedsLogin {
		// Login redirect parameter is whatever Login needs; pass through.
		h.Login(httpClient, email, password, parseRedirectParam(res.Location))
		res = h.Authorize(httpClient, params)
	}
	if !res.NeedsConsent {
		t.Fatalf("expected consent redirect, got %+v", res)
	}
	code := h.GrantConsent(httpClient, res.SessionID, strings.Fields(scope), false)
	if code == "" {
		t.Fatal("no auth code from GrantConsent")
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code_verifier": {verifier},
	}
	resp, err := http.PostForm(h.Issuer+"/oauth/token", form)
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/oauth/token: status %d, body %s", resp.StatusCode, body)
	}
	var tr e2e.TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tr.AccessToken == "" {
		t.Fatal("empty access_token from /oauth/token")
	}
	return &tr
}

// parseRedirectParam pulls the `redirect` query parameter out of the
// location URL the AS returns when the user is not yet logged in. The
// AS encodes the post-login destination there; Login needs it to bounce
// the browser back to /oauth/authorize.
func parseRedirectParam(location string) string {
	u, err := url.Parse(location)
	if err != nil {
		return ""
	}
	return u.Query().Get("redirect")
}

// TestAdmin_RevokeBrokerGrant_NoCascade verifies that
// DELETE /admin/grants/broker/{id} does NOT touch any unrelated
// issuance rows for the same user — the cascade only flows from
// consent_grants → issuances, not from broker_grants.
//
// Setup: drive a /connect for the broker resource, then a Mint issuance
// for the same user (against an actor MCP). Revoke the broker grant
// and assert the Mint issuance's revoked_at stays nil. The original
// test inserted a Broker-kind issuance row via the store; this version
// uses a Mint issuance because the public surface only lets us drive
// Broker-kind issuances through the upstream-vend path which returns
// the upstream credential as the access token — not what this test
// exercises. The load-bearing assertion (no cascade from broker grant
// revoke to other issuances) is unchanged.
func TestAdmin_RevokeBrokerGrant_NoCascade(t *testing.T) {
	// client_ids are auto-generated; mcpSlug stays operator-meaningful.
	const (
		mcpSlug      = "rbg-nocascade-mcp"
		providerSlug = "rbg-nocascade-bp"
		email        = "alice-rbgnocascade@example.com"
		password     = "pass123"
	)

	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI:             true,
		EnableTokenExchange:        true,
		TokenExchangeMaxChainDepth: 5,
		Connectors: []e2e.ConnectorConfig{
			{
				Service:      providerSlug,
				Scopes:       []string{"scope1"},
				AccessToken:  "mock-broker-access-token",
				RefreshToken: "mock-broker-refresh-token",
				ExpiresIn:    3600,
			},
		},
	}, scopes)

	rs := servers[0]
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")
	userID := h.CreateUser(email, password)

	webAppClientID := h.AdminCreatePublicClient("rbg-nocascade webapp", []string{"authorization_code"}, "tools/echo", nil)
	mcpServerClientID, mcpSecret := h.AdminCreateConfidentialClient(
		"rbg-nocascade mcp",
		[]string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		"tools/echo",
	)

	mockBase := h.MockUpstreamURL(providerSlug)
	h.AdminCreateBrokerProvider(e2e.CreateBrokerProviderSpec{
		Slug:        providerSlug,
		DisplayName: providerSlug,
		Protocol:    "oauth",
		ConfigData: map[string]any{
			"client_id":         "mock-client-id",
			"client_secret_env": "CONNECTOR_E2E_MOCK_SECRET",
			"authorize_url":     mockBase + "/authorize",
			"token_url":         mockBase + "/token",
			"response_format":   "standard",
		},
	})
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:               providerSlug,
		URI:                "https://" + providerSlug + ".test",
		BackendKind:        "broker",
		BrokerProviderSlug: providerSlug,
		DisplayName:        providerSlug,
		Scopes: []e2e.AdminScope{
			{Name: "scope1", Upstream: "scope1"},
		},
	})
	h.RunFlowConnect(email, password, providerSlug)

	// Mint actor-MCP resource + consent + issuance for the same user.
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:        mcpSlug,
		URI:         "https://" + mcpSlug + ".test",
		BackendKind: "mint",
		DisplayName: "mcp:" + mcpSlug,
		Scopes: []e2e.AdminScope{
			{Name: "tools/echo"},
		},
		Policy: &e2e.AdminPolicy{
			Runtime: e2e.AdminRuntimePolicy{ClientIDs: []string{mcpServerClientID}},
		},
	})
	h.RunFlowC1Consent(
		email, password, webAppClientID, "http://localhost:9999/callback",
		mcpSlug,
		[]string{"tools/echo"}, []string{"tools/echo"},
	)
	mcpClient := e2e.NewMCPClient(t, h, rs, webAppClientID, "http://localhost:9999/callback")
	userTokens := mcpClient.FullFlow(email, password, "tools/echo", false)
	exch := h.TokenExchangeWithResource(
		mcpServerClientID, mcpSecret,
		userTokens.AccessToken, tokenTypeAccessToken,
		"tools/echo",
		mcpSlug,
	)
	if exch.AccessToken == "" {
		t.Fatal("expected exchanged access token")
	}

	// Resolve broker grant id + Mint issuance id via the admin API. The
	// auth-code flow against mcp-0 produces a consent_grants row but not
	// an issuance (mint_issuer.Issue only writes when req.Resource is
	// set, which the token-exchange path does and the auth-code path
	// does not). Find the actor-MCP issuance explicitly.
	grants := listUserGrants(t, h, userID)
	if len(grants.BrokerGrants) != 1 {
		t.Fatalf("expected 1 broker grant pre-revoke, got %d", len(grants.BrokerGrants))
	}
	bgID := grants.BrokerGrants[0].ID

	mcpRes := h.AdminGetResourceBySlug(mcpSlug)
	issList := listIssuancesByQuery(t, h, "user="+userID)
	var mintIssuanceID string
	for _, r := range issList {
		if r.ResourceID == mcpRes.ID {
			mintIssuanceID = r.ID
			break
		}
	}
	if mintIssuanceID == "" {
		t.Fatalf("expected an issuance against actor MCP resource, got %d total rows", len(issList))
	}

	revResp := h.AdminRequest("DELETE", "/admin/grants/broker/"+bgID, nil)
	revResp.Body.Close()
	if revResp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke status: %d", revResp.StatusCode)
	}

	// Issuance unchanged — no cascade from broker grant revoke.
	post := getIssuanceByID(t, h, mintIssuanceID)
	if post.RevokedAt != nil {
		t.Errorf("Mint issuance revoked unexpectedly after broker-grant revoke (no cascade expected): %v", post.RevokedAt)
	}
}

// adminIssuanceFullView mirrors the dto.IssuanceView shape (renamed to
// avoid collision with agent_identity_unified_test.go's narrower
// adminIssuanceView). RevokedAt is *time.Time per the wire contract;
// this file's tests need the nil-vs-non-nil signal.
type adminIssuanceFullView struct {
	ID            string     `json:"id"`
	JTI           string     `json:"jti"`
	SubjectUserID string     `json:"subject_user_id"`
	ClientID      string     `json:"client_id"`
	ResourceID    string     `json:"resource_id"`
	Scopes        []string   `json:"scopes"`
	BackendKind   string     `json:"backend_kind"`
	IssuedAt      string     `json:"issued_at"`
	ExpiresAt     string     `json:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
}

// listIssuancesByQuery performs GET /admin/issuances?<query> and
// decodes the response rows.
func listIssuancesByQuery(t *testing.T, h *e2e.TestHarness, query string) []adminIssuanceFullView {
	t.Helper()
	path := "/admin/issuances"
	if query != "" {
		path = path + "?" + query
	}
	resp := h.AdminRequest("GET", path, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s: status %d, body %s", path, resp.StatusCode, raw)
	}
	var body struct {
		Issuances []adminIssuanceFullView `json:"issuances"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode issuances list: %v", err)
	}
	return body.Issuances
}

// getIssuanceByID performs GET /admin/issuances/{id} and decodes the row.
func getIssuanceByID(t *testing.T, h *e2e.TestHarness, issuanceID string) adminIssuanceFullView {
	t.Helper()
	resp := h.AdminRequest("GET", "/admin/issuances/"+issuanceID, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /admin/issuances/%s: status %d, body %s", issuanceID, resp.StatusCode, raw)
	}
	var out adminIssuanceFullView
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode issuance %s: %v", issuanceID, err)
	}
	return out
}
