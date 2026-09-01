//go:build e2e

package scenarios

import (
	"net/url"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// TestGatewayFanout_MintToBroker_PathA_Happy is the T12 end-to-end test
// for the fronted Mint→Broker happy path (Path A).
//
// Flow:
//  1. Use gatewayFanoutBrokerSetup (T11) to spin up the fixture:
//     source Mint fb-mcp-gw, broker fb-google-cal, fronting link, agent.
//  2. User pre-connects to google-cal granting [calendar.readonly] via the
//     public /connect/<slug> dance (h.RunFlowConnect). The mock upstream
//     returns "goog_fb_mock_token" on the refresh_token vend path.
//  3. The user drives PKCE at fb-mcp-gw to obtain a GW token with
//     scope=tool:list (RunFlowC1Consent + ExchangeCode). The GW token
//     carries aud=https://fb-mcp-gw.test — required for
//     resolveSourceForFronting to walk the audience and find the
//     source resource row.
//  4. The agent calls /oauth/token with grant_type=token-exchange,
//     subject_token=<GW token>, resource=fb-google-cal, scope=tool:list.
//     dispatchFrontedBroker translates tool:list→readonly and vends the
//     upstream token (goog_fb_mock_token) from the mock via
//     brokerproto/oauth's refresh_token grant.
//  5. Assert: access_token == "goog_fb_mock_token", token_type == "Bearer".
//  6. Assert audit: the token.exchanged row carries chain_kind=fronted,
//     target_kind=broker, via_link=fb-mcp-gw->fb-google-cal.
func TestGatewayFanout_MintToBroker_PathA_Happy(t *testing.T) {
	fix := gatewayFanoutBrokerSetup(t)
	h := fix.h
	agentSecret := fix.agentSecret

	// Step 1: User pre-connects to google-cal.
	// RunFlowConnect drives the full /connect/<slug> dance against the
	// in-process mock upstream and persists a BrokerGrant for
	// (alice-fb@example.com, google-cal). The mock returns
	// "goog_fb_mock_token" on the authorization_code and refresh_token
	// grants, so any subsequent vend will hand back that token.
	h.RunFlowConnect(fbEmail, fbPassword, fbCalProviderSlug)

	// Step 2: User obtains a GW token for tool:list.
	// RunFlowC1Consent runs PKCE at the source Mint (fb-mcp-gw) and
	// returns the auth code + PKCE verifier. ExchangeCode redeems the
	// code for tokens; the resulting access token carries
	// aud=https://fb-mcp-gw.test which resolveSourceForFronting uses
	// to locate the source resource row.
	code, verifier, _ := h.RunFlowC1Consent(
		fbEmail, fbPassword,
		fix.gwClient, fbGWRedirect,
		fbGWSlug,
		[]string{"tool:list"},
		[]string{"tool:list"},
	)
	if code == "" {
		t.Fatal("RunFlowC1Consent at fb-mcp-gw returned empty code")
	}
	gwTokens := h.ExchangeCode(code, verifier, fix.gwClient, fbGWRedirect)
	if gwTokens.AccessToken == "" {
		t.Fatal("ExchangeCode returned empty access_token")
	}

	// Sanity: GW token audience must be the source Mint URI so
	// resolveSourceForFronting can resolve it.
	gwClaims := parseJWTClaims(t, gwTokens.AccessToken)
	if got := audAsString(gwClaims["aud"]); got != fbGWURI {
		t.Fatalf("GW token aud = %q, want %q (fronting source resolution walks aud)", got, fbGWURI)
	}

	// Step 3: Agent performs the fronted exchange.
	// scope=readonly is the TARGET-SIDE scope; validateBrokerTargets verifies
	// (a) "readonly" is declared as a value in the link's ScopeMap and (b)
	// the source key mapping to it ("tool:list") is in the GW token's
	// scope claim. Validation passes → BrokerIssuer.Issue is called.
	// resource=fbCalSlug selects the broker target.
	exch := h.TokenExchangeWithResource(
		fix.agentClient, agentSecret,
		gwTokens.AccessToken,
		"urn:ietf:params:oauth:token-type:access_token",
		"readonly",
		fbCalSlug,
	)

	// Step 4: Assert response shape.
	// The mock upstream echoes "goog_fb_mock_token" on any refresh_token
	// grant (the vend path the brokerproto/oauth adapter uses).
	// Broker responses are opaque upstream tokens, NOT AS-issued JWTs.
	if exch.AccessToken != "goog_fb_mock_token" {
		t.Errorf("access_token = %q, want goog_fb_mock_token (mock upstream vend token)", exch.AccessToken)
	}
	if exch.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", exch.TokenType)
	}

	// Step 5: Assert audit detail carries fronted-broker labels.
	// auditDetailContainsAll queries GET /admin/audit?action=token.exchanged
	// and returns true iff at least one row's Detail contains every needle.
	wantViaLink := fbGWSlug + "->" + fbCalSlug
	if !auditDetailContainsAll(t, h, "token.exchanged",
		"chain_kind=fronted",
		"target_kind=broker",
		"via_link="+wantViaLink,
	) {
		t.Errorf("expected an audit row with chain_kind=fronted, target_kind=broker, via_link=%s", wantViaLink)
	}
}

// fronted Mint→Broker fixture constants.
// Shared by gatewayFanoutBrokerSetup and all path tests (T12–T14).
const (
	fbGWSlug  = "fb-mcp-gw"
	fbGWURI   = "https://fb-mcp-gw.test"
	fbGWScope = "tool:list tool:create"

	fbCalProviderSlug = "google-cal"
	fbCalSlug         = "fb-google-cal"
	fbCalURI          = "https://fb-google-cal.test"

	fbEmail    = "alice-fb@example.com"
	fbPassword = "pass123"

	fbGWRedirect = "http://localhost:9999/callback"
)

// fanoutBrokerFixture bundles the runtime-assigned client_ids alongside the
// harness so tests no longer rely on the retired slug==client_id convention
// . Every client_id is auto-generated by the AS at registration time
// and must be carried through the test by reference.
type fanoutBrokerFixture struct {
	h           *e2e.TestHarness
	gwClient    string
	agentClient string
	agentSecret string
}

// gatewayFanoutBrokerSetup spins up the full Mint→Broker fronted-exchange
// fixture used by T12 (Path A — happy), T13 (Path B/B' — reconnect), and
// T14 (Path C — no connection). It returns the TestHarness and the agent
// client secret (which is generated fresh each run and cannot be re-derived).
//
// Fixture:
//   - Source Mint: fb-mcp-gw    scopes=[tool:list, tool:create]
//   - Broker provider: google-cal  backed by in-process mock upstream
//   - Broker resource: fb-google-cal  scopes=[readonly→calendar.readonly, events→calendar.events]
//   - Fronting link: fb-mcp-gw → fb-google-cal
//     scope_map: {tool:list:[readonly], tool:create:[events]}
//   - User: alice-fb@example.com / pass123
//   - Public GW client (client_id == "fb-mcp-gw")
//   - Agent client "fb-fanout-agent" (confidential, token-exchange grant)
//
// The mock upstream is wired via HarnessConfig.Connectors so
// h.MockUpstreamURL("google-cal") returns its base URL for config_data.
// The mock returns "goog_fb_mock_token" on both authorization_code and
// refresh_token grants.
func gatewayFanoutBrokerSetup(t *testing.T) fanoutBrokerFixture {
	t.Helper()

	// SetupE2E starts the AS and a placeholder Mint resource (the two-phase
	// setup requires at least one resource slot). The Connectors entry
	// spins up an in-process mock upstream OAuth server that
	// brokerproto/oauth will call during /connect and vend flows.
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI:             true,
		EnableTokenExchange:        true,
		TokenExchangeMaxChainDepth: 5,
		Connectors: []e2e.ConnectorConfig{
			{
				Service: fbCalProviderSlug,
				Scopes:  []string{"calendar.readonly", "calendar.events"},
				// The mock upstream's /token handler echoes the refresh_token
				// as the access_token on grant_type=refresh_token (the Vend
				// path). Setting both to the same value makes the vended
				// token predictable for T12 assertions.
				AccessToken:  "goog_fb_mock_token",
				RefreshToken: "goog_fb_mock_token",
				ExpiresIn:    3600,
			},
		},
	}, []string{"placeholder"})

	// 1. User.
	h.CreateUser(fbEmail, fbPassword)

	// 2. Clients before resources — AdminCreateResource validates that every
	//    client_id in policy.exchange.allowed_client_ids already exists.
	// client_ids are auto-generated by the AS; Option β substitutes
	// the source slug as the issued JWT's client_id at dispatch time, so the
	// gateway's actual OAuth client_id is independent of fbGWSlug.
	gwClient := h.AdminCreatePublicClient(
		" fanout gateway",
		[]string{"authorization_code"},
		fbGWScope,
		[]string{fbGWRedirect},
	)

	// Agent client: confidential, flagged IsAgent, token-exchange grant.
	// The agent drives the fronted exchange on behalf of the MCP gateway.
	agentClient, agentSecret := h.AdminCreateAgentClient(
		" fronted Mint→Broker fanout agent",
		[]string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		"tool:list tool:create calendar.readonly calendar.events",
		" fronted Mint→Broker fanout agent",
	)

	// 3. Source Mint resource (fb-mcp-gw).
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:        fbGWSlug,
		URI:         fbGWURI,
		BackendKind: "mint",
		DisplayName: "MCP Gateway (fronted broker fixture)",
		Scopes: []e2e.AdminScope{
			{Name: "tool:list"},
			{Name: "tool:create"},
		},
	})

	// 4. Broker provider + Broker resource (fb-google-cal).
	//
	// config_data wires the brokerproto/oauth adapter at the mock upstream.
	// The authorize_url and token_url point at the in-process server started
	// by SetupE2E for the "google-cal" ConnectorConfig entry.
	mockBase := h.MockUpstreamURL(fbCalProviderSlug)
	h.AdminCreateBrokerProvider(e2e.CreateBrokerProviderSpec{
		Slug:        fbCalProviderSlug,
		DisplayName: "Google Calendar (mock)",
		Protocol:    "oauth",
		ConfigData: map[string]any{
			"client_id":         "mock-google-client-id",
			"client_secret_ref": "CONNECTOR_E2E_MOCK_SECRET",
			"authorize_url":     mockBase + "/authorize",
			"token_url":         mockBase + "/token",
			"response_format":   "standard",
		},
	})
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:               fbCalSlug,
		URI:                fbCalURI,
		BackendKind:        "broker",
		BrokerProviderSlug: fbCalProviderSlug,
		DisplayName:        "Google Calendar resource (fronted broker fixture)",
		Scopes: []e2e.AdminScope{
			// Name is the resource-level scope token; Upstream is the
			// provider-fine scope the brokerproto/oauth adapter requests.
			{Name: "readonly", Upstream: "calendar.readonly"},
			{Name: "events", Upstream: "calendar.events"},
		},
		// The agent client must be on the exchange allowlist so
		// dispatchBroker's bound-B operator gate permits the exchange.
		Policy: &e2e.AdminPolicy{
			Exchange: e2e.AdminExchangePolicy{
				AllowedClientIDs: []string{agentClient},
			},
		},
	})

	// 5. Fronting link: fb-mcp-gw → fb-google-cal.
	//
	// scope_map entries are: source-side MCP scope → [broker-resource scope(s)].
	// dispatchFrontedBroker calls requiredBrokerScopesForTargets(link.ScopeMap,
	// requestedSourceScopes) which translates each source scope into the set
	// of broker-resource scope names to vend from the upstream.
	h.AdminCreateFrontingLink(e2e.CreateFrontingLinkSpec{
		Source: fbGWSlug,
		Target: fbCalSlug,
		ScopeMap: map[string][]string{
			"tool:list":   {"readonly"},
			"tool:create": {"events"},
		},
	})

	return fanoutBrokerFixture{h: h, gwClient: gwClient, agentClient: agentClient, agentSecret: agentSecret}
}

// TestGatewayFanout_MintToBroker_PathB_ReconnectThenRecover is the T13
// end-to-end test for the fronted Mint→Broker denial (Path B) and
// subsequent recovery (Path B').
//
// Path B — consent_required when upstream scopes are insufficient:
//
//  1. Spin up the fixture with a mock upstream that only grants
//     [calendar.readonly]. The agent requests tool:create which maps to
//     "events" via the scope_map — "events" is NOT in the grant.
//  2. Token-exchange must return consent_required.
//  3. consent_url must point at /connect/google-cal?return_url=.../connections.
//  4. The token.exchange_denied audit row must carry chain_kind=fronted,
//     target_kind=broker, denied_reason=upstream_scope_insufficient.
//
// Path B' — recovery after reconnect with expanded scopes:
//
//  5. Spin up a second harness (same fixture shape but mock grants BOTH
//     scopes). RunFlowConnect upserts the grant with calendar.events.
//  6. The agent retries the exchange for tool:create — this time it
//     succeeds and access_token is "goog_fb_mock_token".
//
// The two harnesses are isolated sub-tests (t.Run) so a Path B failure
// does not mask a Path B' regression. Each creates its own in-memory
// SQLite + httptest.Server (standard harness pattern).
func TestGatewayFanout_MintToBroker_PathB_ReconnectThenRecover(t *testing.T) {
	// ---- Path B — consent_required (upstream scope insufficient) ----
	t.Run("PathB_ConsentRequired", func(t *testing.T) {
		// Custom setup: mock upstream grants ONLY calendar.readonly so the
		// first RunFlowConnect produces a grant that lacks calendar.events.
		// tool:create→events mapping (see scope_map) therefore fails with
		// consent_required / upstream_scope_insufficient.
		fix := gatewayFanoutBrokerSetupCustomScopes(t,
			[]string{"calendar.readonly"}, // upstream grants only this
			"goog_fb_mock_token_b",
		)
		h := fix.h
		agentSecret := fix.agentSecret

		// Step 1: User pre-connects — mock returns only calendar.readonly.
		h.RunFlowConnect(fbEmail, fbPassword, fbCalProviderSlug)

		// Step 2: User obtains a GW token with scope=tool:create.
		// tool:create maps to broker scope "events" via the link scope_map.
		code, verifier, _ := h.RunFlowC1Consent(
			fbEmail, fbPassword,
			fix.gwClient, fbGWRedirect,
			fbGWSlug,
			[]string{"tool:create"},
			[]string{"tool:create"},
		)
		if code == "" {
			t.Fatal("RunFlowC1Consent for tool:create returned empty code")
		}
		gwTokens := h.ExchangeCode(code, verifier, fix.gwClient, fbGWRedirect)
		if gwTokens.AccessToken == "" {
			t.Fatal("ExchangeCode returned empty access_token")
		}

		// Step 3: Token-exchange — expect consent_required.
		// TokenExchangeWithResourceExpectError calls POST /oauth/token and
		// returns the OAuthError on any non-200 response. The fronted
		// dispatch path (dispatchFrontedBroker) calls BrokerIssuer.Issue
		// which detects that calendar.events is not in the stored grant and
		// returns ConsentRequiredError{Cause: CauseScopeInsufficient}.
		oe := h.TokenExchangeWithResourceExpectError(
			fix.agentClient, agentSecret,
			gwTokens.AccessToken,
			"urn:ietf:params:oauth:token-type:access_token",
			"events",
			fbCalSlug,
		)

		// Step 4: Assert error code.
		if oe.Error != "consent_required" {
			t.Errorf("error = %q, want consent_required", oe.Error)
		}

		// Step 5: Assert consent_url shape.
		// The HTTP handler builds the URL via connection.ConsentURL:
		//   <issuer>/connect/<providerSlug>?return_url=<issuer>/connections
		// The fronted dispatch does NOT enrich ResourceSlug (it returns the
		// ConsentRequiredError from BrokerIssuer verbatim), so the ?resource=
		// query parameter is absent here — unlike the direct-broker path
		// (connection_token_exchange_test.go L254) which wraps the error with
		// both ProviderSlug and ResourceSlug.
		expectedConsentURLPrefix := h.Issuer + "/connect/" + fbCalProviderSlug
		if !strings.HasPrefix(oe.ConsentURL, expectedConsentURLPrefix) {
			t.Errorf("consent_url = %q, want prefix %q", oe.ConsentURL, expectedConsentURLPrefix)
		}
		// The return_url must point at the AS /connections page.
		expectedReturnURL := h.Issuer + "/connections"
		parsedConsent, err := url.Parse(oe.ConsentURL)
		if err != nil {
			t.Fatalf("parse consent_url %q: %v", oe.ConsentURL, err)
		}
		if got := parsedConsent.Query().Get("return_url"); got != expectedReturnURL {
			t.Errorf("consent_url return_url = %q, want %q", got, expectedReturnURL)
		}

		// Step 6: Audit assertion — denial event with upstream_scope_insufficient.
		wantViaLink := fbGWSlug + "->" + fbCalSlug
		if !auditDetailContainsAll(t, h, "token.exchange_denied",
			"chain_kind=fronted",
			"target_kind=broker",
			"denied_reason=upstream_scope_insufficient",
			"via_link="+wantViaLink,
		) {
			t.Errorf("expected audit row with chain_kind=fronted, target_kind=broker, "+
				"denied_reason=upstream_scope_insufficient, via_link=%s", wantViaLink)
		}
	})

	// ---- Path B' — recovery after reconnect with expanded scopes ----
	t.Run("PathBPrime_Recovery", func(t *testing.T) {
		// Setup: mock upstream grants BOTH calendar.readonly AND
		// calendar.events. After RunFlowConnect the grant has both scopes,
		// so the tool:create exchange (→ events) succeeds.
		//
		// This models the real recovery flow:
		//   1. User previously connected with limited scopes.
		//   2. System prompts the user to re-connect (Path B consent_url).
		//   3. User re-drives /connect/<provider>; the mock now returns the
		//      expanded scope set. RunFlowConnect upserts the grant.
		//   4. Agent retries the exchange — now it succeeds.
		//
		// Since the E2E mock upstream cannot change its grant set
		// mid-test (scopes are fixed at harness creation time), Path B'
		// uses a separate harness that was configured from the start with
		// both scopes. This correctly exercises the recovery code path:
		// the exchange service and BrokerIssuer see a grant covering the
		// requested upstream scope and proceed to vend.
		fix := gatewayFanoutBrokerSetup(t) // both scopes
		h := fix.h
		agentSecret := fix.agentSecret

		// User connects — mock grants calendar.readonly + calendar.events.
		h.RunFlowConnect(fbEmail, fbPassword, fbCalProviderSlug)

		// User obtains a GW token with scope=tool:create.
		code, verifier, _ := h.RunFlowC1Consent(
			fbEmail, fbPassword,
			fix.gwClient, fbGWRedirect,
			fbGWSlug,
			[]string{"tool:create"},
			[]string{"tool:create"},
		)
		if code == "" {
			t.Fatal("RunFlowC1Consent for tool:create (recovery) returned empty code")
		}
		gwTokens := h.ExchangeCode(code, verifier, fix.gwClient, fbGWRedirect)
		if gwTokens.AccessToken == "" {
			t.Fatal("ExchangeCode (recovery) returned empty access_token")
		}

		// Token-exchange — must succeed this time.
		exch := h.TokenExchangeWithResource(
			fix.agentClient, agentSecret,
			gwTokens.AccessToken,
			"urn:ietf:params:oauth:token-type:access_token",
			"events",
			fbCalSlug,
		)

		// The mock echoes "goog_fb_mock_token" on any refresh_token grant.
		if exch.AccessToken != "goog_fb_mock_token" {
			t.Errorf("recovery access_token = %q, want goog_fb_mock_token", exch.AccessToken)
		}
		if exch.TokenType != "Bearer" {
			t.Errorf("recovery token_type = %q, want Bearer", exch.TokenType)
		}

		// Audit: successful fronted exchange carries chain_kind=fronted,
		// target_kind=broker, via_link — no denied_reason on success.
		wantViaLink := fbGWSlug + "->" + fbCalSlug
		if !auditDetailContainsAll(t, h, "token.exchanged",
			"chain_kind=fronted",
			"target_kind=broker",
			"via_link="+wantViaLink,
		) {
			t.Errorf("recovery: expected audit row with chain_kind=fronted, target_kind=broker, via_link=%s", wantViaLink)
		}
	})
}

// gatewayFanoutBrokerSetupCustomScopes is a variant of gatewayFanoutBrokerSetup
// for Path B tests that require the mock upstream to grant a restricted scope
// set (e.g. [calendar.readonly] only). accessToken is the fixed upstream
// token the mock will return on both the authorization_code and refresh_token
// grant paths.
//
// All other fixture parameters (resources, fronting link, scope_map, clients)
// are identical to gatewayFanoutBrokerSetup. The connector differs only in
// the Scopes slice, which the mock upstream echoes back as the `scope`
// response field. The ConnectService stores those scopes in the BrokerGrant's
// ScopesGranted so BrokerIssuer.Issue can enforce the upstream scope check.
func gatewayFanoutBrokerSetupCustomScopes(
	t *testing.T,
	upstreamScopes []string, // scopes the mock upstream will grant
	accessToken string, // predictable token value for assertions
) fanoutBrokerFixture {
	t.Helper()

	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI:             true,
		EnableTokenExchange:        true,
		TokenExchangeMaxChainDepth: 5,
		Connectors: []e2e.ConnectorConfig{
			{
				Service:      fbCalProviderSlug,
				Scopes:       upstreamScopes,
				AccessToken:  accessToken,
				RefreshToken: accessToken, // echo-through so vend returns accessToken
				ExpiresIn:    3600,
			},
		},
	}, []string{"placeholder"})

	h.CreateUser(fbEmail, fbPassword)
	gwClient := h.AdminCreatePublicClient(
		" fanout gateway (custom scopes)",
		[]string{"authorization_code"},
		fbGWScope,
		[]string{fbGWRedirect},
	)
	agentClient, agentSecret := h.AdminCreateAgentClient(
		" fronted Mint→Broker fanout agent (custom scopes)",
		[]string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		"tool:list tool:create calendar.readonly calendar.events",
		" fronted Mint→Broker fanout agent (custom scopes)",
	)
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:        fbGWSlug,
		URI:         fbGWURI,
		BackendKind: "mint",
		DisplayName: "MCP Gateway (fronted broker fixture — custom scopes)",
		Scopes: []e2e.AdminScope{
			{Name: "tool:list"},
			{Name: "tool:create"},
		},
	})
	mockBase := h.MockUpstreamURL(fbCalProviderSlug)
	h.AdminCreateBrokerProvider(e2e.CreateBrokerProviderSpec{
		Slug:        fbCalProviderSlug,
		DisplayName: "Google Calendar (mock, custom scopes)",
		Protocol:    "oauth",
		ConfigData: map[string]any{
			"client_id":         "mock-google-client-id",
			"client_secret_ref": "CONNECTOR_E2E_MOCK_SECRET",
			"authorize_url":     mockBase + "/authorize",
			"token_url":         mockBase + "/token",
			"response_format":   "standard",
		},
	})
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:               fbCalSlug,
		URI:                fbCalURI,
		BackendKind:        "broker",
		BrokerProviderSlug: fbCalProviderSlug,
		DisplayName:        "Google Calendar resource (fronted broker fixture — custom scopes)",
		Scopes: []e2e.AdminScope{
			{Name: "readonly", Upstream: "calendar.readonly"},
			{Name: "events", Upstream: "calendar.events"},
		},
		Policy: &e2e.AdminPolicy{
			Exchange: e2e.AdminExchangePolicy{
				AllowedClientIDs: []string{agentClient},
			},
		},
	})
	h.AdminCreateFrontingLink(e2e.CreateFrontingLinkSpec{
		Source: fbGWSlug,
		Target: fbCalSlug,
		ScopeMap: map[string][]string{
			"tool:list":   {"readonly"},
			"tool:create": {"events"},
		},
	})

	return fanoutBrokerFixture{h: h, gwClient: gwClient, agentClient: agentClient, agentSecret: agentSecret}
}

// TestGatewayFanout_MintToBroker_PathC_NoConnection is the T14 end-to-end test
// for the fronted Mint→Broker denial (Path C — no upstream connection at all).
//
// Flow:
//  1. Use gatewayFanoutBrokerSetup (T11) to spin up the fixture.
//     Critically, RunFlowConnect is NOT called — the user has never
//     connected to google-cal, so there is no BrokerGrant row.
//  2. User obtains a GW token for tool:list via PKCE at fb-mcp-gw
//     (RunFlowC1Consent + ExchangeCode). This part is identical to Path A.
//  3. Agent performs the fronted exchange targeting fb-google-cal with
//     scope=tool:list. dispatchFrontedBroker calls BrokerIssuer.Issue;
//     there is no stored grant, so it returns
//     ConsentRequiredError{Cause: CauseConsentMissing}.
//     The T9 audit mapper sets denied_reason=upstream_connection_missing.
//  4. Assert: error == "consent_required".
//  5. Assert: consent_url has prefix <issuer>/connect/google-cal.
//  6. Assert: audit row carries chain_kind=fronted, target_kind=broker,
//     denied_reason=upstream_connection_missing,
//     via_link=fb-mcp-gw->fb-google-cal.
func TestGatewayFanout_MintToBroker_PathC_NoConnection(t *testing.T) {
	fix := gatewayFanoutBrokerSetup(t)
	h := fix.h
	agentSecret := fix.agentSecret

	// Step 1: NO RunFlowConnect — fresh user, no upstream grant.
	// The BrokerGrant table has no row for (alice-fb, google-cal).
	// BrokerIssuer.Issue will return ConsentRequiredError{Cause: CauseConsentMissing}
	// which the T9 audit mapper converts to denied_reason=upstream_connection_missing.

	// Step 2: User obtains a GW token for tool:list.
	// This mirrors Path A step 2 — we still need a valid GW token with
	// aud=https://fb-mcp-gw.test for resolveSourceForFronting to work.
	code, verifier, _ := h.RunFlowC1Consent(
		fbEmail, fbPassword,
		fix.gwClient, fbGWRedirect,
		fbGWSlug,
		[]string{"tool:list"},
		[]string{"tool:list"},
	)
	if code == "" {
		t.Fatal("RunFlowC1Consent at fb-mcp-gw returned empty code")
	}
	gwTokens := h.ExchangeCode(code, verifier, fix.gwClient, fbGWRedirect)
	if gwTokens.AccessToken == "" {
		t.Fatal("ExchangeCode returned empty access_token")
	}

	// Step 3: Token-exchange — expect consent_required.
	// dispatchFrontedBroker → BrokerIssuer.Issue finds no BrokerGrant for
	// the user and returns ConsentRequiredError{Cause: CauseConsentMissing}.
	oe := h.TokenExchangeWithResourceExpectError(
		fix.agentClient, agentSecret,
		gwTokens.AccessToken,
		"urn:ietf:params:oauth:token-type:access_token",
		"readonly",
		fbCalSlug,
	)

	// Step 4: Assert error code.
	if oe.Error != "consent_required" {
		t.Errorf("error = %q, want consent_required", oe.Error)
	}

	// Step 5: Assert consent_url shape — same as Path B.
	// The HTTP handler builds: <issuer>/connect/<providerSlug>?return_url=<issuer>/connections
	expectedConsentURLPrefix := h.Issuer + "/connect/" + fbCalProviderSlug
	if !strings.HasPrefix(oe.ConsentURL, expectedConsentURLPrefix) {
		t.Errorf("consent_url = %q, want prefix %q", oe.ConsentURL, expectedConsentURLPrefix)
	}
	expectedReturnURL := h.Issuer + "/connections"
	parsedConsent, err := url.Parse(oe.ConsentURL)
	if err != nil {
		t.Fatalf("parse consent_url %q: %v", oe.ConsentURL, err)
	}
	if got := parsedConsent.Query().Get("return_url"); got != expectedReturnURL {
		t.Errorf("consent_url return_url = %q, want %q", got, expectedReturnURL)
	}

	// Step 6: Audit assertion — denial event with upstream_connection_missing.
	// The T9 mapper: CauseConsentMissing with empty DeniedReason → upstream_connection_missing.
	wantViaLink := fbGWSlug + "->" + fbCalSlug
	if !auditDetailContainsAll(t, h, "token.exchange_denied",
		"chain_kind=fronted",
		"target_kind=broker",
		"denied_reason=upstream_connection_missing",
		"via_link="+wantViaLink,
	) {
		t.Errorf("expected audit row with chain_kind=fronted, target_kind=broker, "+
			"denied_reason=upstream_connection_missing, via_link=%s", wantViaLink)
	}
}

// TestGatewayFanout_MintToBroker_Setup is the T11 smoke test. It verifies
// that the fixture spins up cleanly — all admin registrations succeed and
// the key rows are visible via the admin API — without performing any
// token exchange. Passing this test is a prerequisite for T12–T14.
func TestGatewayFanout_MintToBroker_Setup(t *testing.T) {
	fix := gatewayFanoutBrokerSetup(t)
	h := fix.h
	agentSecret := fix.agentSecret

	if h == nil {
		t.Fatal("setup returned nil harness")
	}
	if agentSecret == "" {
		t.Fatal("setup returned empty agent secret")
	}

	// Smoke: source Mint resource is registered and visible.
	gw := h.AdminGetResourceBySlug(fbGWSlug)
	if gw.ID == "" {
		t.Errorf("AdminGetResourceBySlug(%q): empty ID", fbGWSlug)
	}
	if gw.BackendKind != "mint" {
		t.Errorf("gw.BackendKind = %q, want mint", gw.BackendKind)
	}
	if gw.URI != fbGWURI {
		t.Errorf("gw.URI = %q, want %q", gw.URI, fbGWURI)
	}

	// Smoke: Broker resource is registered and linked to a provider.
	cal := h.AdminGetResourceBySlug(fbCalSlug)
	if cal.ID == "" {
		t.Errorf("AdminGetResourceBySlug(%q): empty ID", fbCalSlug)
	}
	if cal.BackendKind != "broker" {
		t.Errorf("cal.BackendKind = %q, want broker", cal.BackendKind)
	}
	if cal.BrokerProviderID == "" {
		t.Errorf("cal.BrokerProviderID empty — BrokerProviderSlug wiring failed")
	}

	// Smoke: fronting link is present.
	linkResp := h.AdminRequest("GET", "/admin/fronting/"+fbGWSlug+"/"+fbCalSlug, nil)
	defer linkResp.Body.Close()
	if linkResp.StatusCode != 200 {
		t.Errorf("GET /admin/fronting/%s/%s: status %d, want 200 (link must exist after setup)",
			fbGWSlug, fbCalSlug, linkResp.StatusCode)
	}
}
