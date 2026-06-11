//go:build e2e

package scenarios

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/authplane/authserver/e2e"
)

// admin_issuances_test.go covers the GET/DELETE /admin/issuances surface
// end-to-end. It replaces the Gate-0 shortcuts in
// api/admin/handlers_test.go (the TestAdmin_Issuances_* suite at
// L2326-L2602) where each test seeded the issuances table directly via
// stores.Issuance.Insert.  (closes ).
//
// All issuances here are produced by driving a Mint token-exchange
// against an actor MCP — the same code path operators see in
// production. Setup is intentionally heavier than the original (full
// auth-code + per-MCP consent + token exchange) but matches the rest
// of the e2e suite.

// issuanceFlowFixture bundles the state shared across TestAdmin_Issuances_*
// scenarios: an authenticated user, a registered actor MCP (Mint
// resource), a public web-app client, and a confidential MCP client
// that can perform token exchange. Tests call mintIssuance(t, fixture)
// to produce one issuance row each.
type issuanceFlowFixture struct {
	h               *e2e.TestHarness
	rs              *e2e.MCPResourceServer
	UserID          string
	Email           string
	Password        string
	WebAppClientID  string
	MCPClientID     string
	MCPResourceSlug string
	MCPSecret       string
}

// newIssuanceFlowFixture wires the standard setup the issuance tests
// share. Each test gets its own fixture (one user, one resource, one
// actor MCP) so they don't see each other's rows. The slug suffix is
// the test name to keep IDs unique across parallel runs.
func newIssuanceFlowFixture(t *testing.T, slug string) *issuanceFlowFixture {
	t.Helper()
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI:             true,
		EnableTokenExchange:        true,
		TokenExchangeMaxChainDepth: 5,
	}, scopes)
	rs := servers[0]
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	email := "alice-" + slug + "@example.com"
	password := "pass123"
	userID := h.CreateUser(email, password)

	mcpResourceSlug := "iss-" + slug + "-mcp"
	webAppClientID := h.AdminCreatePublicClient("iss-"+slug+"-webapp", []string{"authorization_code"}, "tools/echo", nil)
	mcpClientID, mcpSecret := h.AdminCreateConfidentialClient(
		"iss-"+slug+"-mcp",
		[]string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		"tools/echo",
	)

	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:        mcpResourceSlug,
		URI:         "https://" + mcpResourceSlug + ".test",
		BackendKind: "mint",
		DisplayName: "mcp:" + mcpResourceSlug,
		Scopes: []e2e.AdminScope{
			{Name: "tools/echo"},
		},
		Policy: &e2e.AdminPolicy{
			Runtime: e2e.AdminRuntimePolicy{ClientIDs: []string{mcpClientID}},
		},
	})
	h.RunFlowC1Consent(
		email, password, webAppClientID, "http://localhost:9999/callback",
		mcpResourceSlug,
		[]string{"tools/echo"}, []string{"tools/echo"},
	)

	return &issuanceFlowFixture{
		h:               h,
		rs:              rs,
		UserID:          userID,
		Email:           email,
		Password:        password,
		WebAppClientID:  webAppClientID,
		MCPClientID:     mcpClientID,
		MCPResourceSlug: mcpResourceSlug,
		MCPSecret:       mcpSecret,
	}
}

// mintIssuance drives a fresh user-token + token-exchange to produce
// one issuance row attributed to (UserID, MCPClientID, MCP-resource).
// The new row is returned via the public admin /admin/issuances
// endpoint so the JTI is sourced from the same wire surface tests
// use to assert on it.
func (f *issuanceFlowFixture) mintIssuance(t *testing.T) adminIssuanceFullView {
	t.Helper()
	preCount := len(listIssuancesByQuery(t, f.h, "user="+f.UserID))

	mcpClient := e2e.NewMCPClient(t, f.h, f.rs, f.WebAppClientID, "http://localhost:9999/callback")
	tokens := mcpClient.FullFlow(f.Email, f.Password, "tools/echo", false)
	if tokens.AccessToken == "" {
		t.Fatal("expected user access token from auth-code flow")
	}
	exch := f.h.TokenExchangeWithResource(
		f.MCPClientID, f.MCPSecret,
		tokens.AccessToken, tokenTypeAccessToken,
		"tools/echo",
		f.MCPResourceSlug,
	)
	if exch.AccessToken == "" {
		t.Fatal("expected vended access token from token exchange")
	}

	// Read the new issuance row back through the admin list endpoint.
	// Default 24h window covers a fresh exchange. A larger limit lets
	// us see all rows the fixture has produced so far; the freshest is
	// the one whose IssuedAt is greatest.
	rows := listIssuancesByQuery(t, f.h, "user="+f.UserID+"&limit=100")
	if len(rows) <= preCount {
		t.Fatalf("expected at least %d issuance rows after mint, got %d", preCount+1, len(rows))
	}
	return findFreshestIssuance(t, rows)
}

// findFreshestIssuance returns the row in rows with the greatest
// issued_at timestamp. The admin list endpoint orders newest-first by
// default, so this is rows[0] in production — but keeping the
// timestamp comparison explicit prevents test flakes if the ordering
// is ever loosened.
func findFreshestIssuance(t *testing.T, rows []adminIssuanceFullView) adminIssuanceFullView {
	t.Helper()
	if len(rows) == 0 {
		t.Fatal("no rows to pick from")
	}
	best := rows[0]
	bestT, err := time.Parse(time.RFC3339Nano, best.IssuedAt)
	if err != nil {
		// Fall back to RFC3339 (no fractional seconds).
		bestT, err = time.Parse(time.RFC3339, best.IssuedAt)
		if err != nil {
			t.Fatalf("parse issued_at %q: %v", best.IssuedAt, err)
		}
	}
	for _, r := range rows[1:] {
		rt, err := time.Parse(time.RFC3339Nano, r.IssuedAt)
		if err != nil {
			rt, err = time.Parse(time.RFC3339, r.IssuedAt)
			if err != nil {
				continue
			}
		}
		if rt.After(bestT) {
			best, bestT = r, rt
		}
	}
	return best
}

// adminIssuancesEnvelope decodes the IssuanceListResponse envelope
// (issuances + since + count). Tests assert on count + since ad-hoc
// without going through the typed list helper.
type adminIssuancesEnvelope struct {
	Issuances []adminIssuanceFullView `json:"issuances"`
	Since     string                  `json:"since"`
	Count     int                     `json:"count"`
}

// requestIssuances issues GET /admin/issuances?<query> and returns the
// raw response + decoded envelope. Used by tests that need both the
// status code and the envelope (most test the 4xx error path on a bad
// query and need the body bytes for substring checks).
func requestIssuances(t *testing.T, h *e2e.TestHarness, query string) (*http.Response, []byte) {
	t.Helper()
	path := "/admin/issuances"
	if query != "" {
		path = path + "?" + query
	}
	resp := h.AdminRequest("GET", path, nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, body
}

func TestAdmin_Issuances_RequiresAtLeastOneFilter(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI: true,
	}, []string{"tools/echo"})

	resp, body := requestIssuances(t, h, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400 (body: %s)", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte("at least one of")) {
		t.Errorf("expected 'at least one of' in body: %s", body)
	}
}

// relaxed the filter contract: combinations of user/client/resource
// are now accepted (the indexed dimension drives the DB query and the
// remainder applies as an in-memory predicate). The previous "mutually
// exclusive" test became obsolete and is replaced by a positive
// "combined filters narrow the result" assertion in
// TestAdmin_Issuances_CombinedFiltersNarrow below.

func TestAdmin_Issuances_DefaultsTo24hWindow_WithUserOrClient(t *testing.T) {
	f := newIssuanceFlowFixture(t, "default-window")
	f.mintIssuance(t)

	resp, body := requestIssuances(t, f.h, "user="+f.UserID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200: %s", resp.StatusCode, body)
	}
	var env adminIssuancesEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Since == "" {
		t.Error("expected since in response")
	}
	// mintIssuance now produces TWO audit rows per call — one for
	// the auth-code grant (Mint, resource = MCPResourceServer.URI) and one
	// for the subsequent token-exchange (Mint, resource = mcpResourceSlug).
	// Pre- the harness skipped WithResourceRegistry on the token
	// service so the auth-code row was silently dropped, leaving count=1.
	if env.Count != 2 {
		t.Errorf("count: got %d, want 2 (auth_code + token_exchange)", env.Count)
	}
}

func TestAdmin_Issuances_RejectsBadSince(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI: true,
	}, []string{"tools/echo"})
	userID := h.CreateUser("alice-bad-since@example.com", "pass123")

	resp, body := requestIssuances(t, h, "user="+userID+"&since=not-a-time")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400 (body: %s)", resp.StatusCode, body)
	}
}

func TestAdmin_Issuances_RejectsSinceWindowExceeding30Days(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI: true,
	}, []string{"tools/echo"})
	userID := h.CreateUser("alice-30d@example.com", "pass123")
	tooFarBack := time.Now().UTC().Add(-31 * 24 * time.Hour).Format(time.RFC3339)

	resp, body := requestIssuances(t, h, "user="+userID+"&since="+tooFarBack)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400 (body: %s)", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte("30 days")) {
		t.Errorf("expected 30-day error message: %s", body)
	}
}

func TestAdmin_Issuances_JTIFilter_IgnoresSince(t *testing.T) {
	f := newIssuanceFlowFixture(t, "jti-since")
	iss := f.mintIssuance(t)

	// since= would normally exclude rows older than 1 second ago;
	// ?jti= is a point-query and ignores ?since=.
	veryRecent := time.Now().UTC().Add(-1 * time.Second).Format(time.RFC3339)
	resp, body := requestIssuances(t, f.h, "jti="+iss.JTI+"&since="+veryRecent)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200: %s", resp.StatusCode, body)
	}
	var env adminIssuancesEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Count != 1 {
		t.Errorf("count: got %d, want 1 (since must be ignored for jti queries)", env.Count)
	}
}

func TestAdmin_Issuances_LimitTruncatesResponse(t *testing.T) {
	f := newIssuanceFlowFixture(t, "limit")

	// Mint five issuances against the same user; ?limit=2 should clip
	// the response to two rows on the wire.
	for n := 0; n < 5; n++ {
		f.mintIssuance(t)
	}

	resp, body := requestIssuances(t, f.h, "user="+f.UserID+"&limit=2")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d body: %s", resp.StatusCode, body)
	}
	var env adminIssuancesEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(env.Issuances) != 2 {
		t.Errorf("issuances len: got %d, want 2 (truncated by limit)", len(env.Issuances))
	}
	if env.Count != 2 {
		t.Errorf("count: got %d, want 2", env.Count)
	}
}

func TestAdmin_Issuances_RejectsBadLimit(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI: true,
	}, []string{"tools/echo"})
	userID := h.CreateUser("alice-bad-limit@example.com", "pass123")

	for _, q := range []string{"limit=0", "limit=-1", "limit=5001", "limit=foo"} {
		resp, body := requestIssuances(t, h, "user="+userID+"&"+q)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400 (body: %s)", q, resp.StatusCode, body)
		}
	}
}

func TestAdmin_Issuances_GetByID(t *testing.T) {
	f := newIssuanceFlowFixture(t, "getbyid")
	iss := f.mintIssuance(t)

	got := getIssuanceByID(t, f.h, iss.ID)
	if got.ID != iss.ID {
		t.Errorf("id: got %q, want %q", got.ID, iss.ID)
	}
}

func TestAdmin_Issuances_GetByID_NotFound(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI: true,
	}, []string{"tools/echo"})
	resp := h.AdminRequest("GET", "/admin/issuances/no-such-id", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d, want 404", resp.StatusCode)
	}
}

func TestAdmin_Issuances_FilterByJTI(t *testing.T) {
	f := newIssuanceFlowFixture(t, "filter-jti-hit")
	iss := f.mintIssuance(t)

	resp, body := requestIssuances(t, f.h, "jti="+iss.JTI)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d body: %s", resp.StatusCode, body)
	}
	var env adminIssuancesEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(env.Issuances) != 1 {
		t.Fatalf("got %d rows, want 1", len(env.Issuances))
	}
	if env.Issuances[0].JTI != iss.JTI {
		t.Errorf("jti: got %q, want %q", env.Issuances[0].JTI, iss.JTI)
	}
}

func TestAdmin_Issuances_FilterByJTI_NotFound_ReturnsEmptyList(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI: true,
	}, []string{"tools/echo"})

	resp, body := requestIssuances(t, h, "jti=no-such-jti")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (NOT 404 — list semantics)", resp.StatusCode)
	}
	var env adminIssuancesEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Issuances == nil {
		t.Error("issuances must be a non-null empty array")
	}
	if len(env.Issuances) != 0 {
		t.Errorf("rows: got %d, want 0", len(env.Issuances))
	}
}

// TestAdmin_Issuances_RevokeReflectsAtAdminGet verifies the admin-side
// half of the revoke round-trip: after DELETE /admin/issuances/{id}
// the row's revoked_at is populated and visible via
// GET /admin/issuances/{id}.
//
// Introspection round-trip deferred: ideally /oauth/introspect would
// return active=false after the admin Revoke. The current
// introspection.IntrospectionService consults output.RevocationStore +
// output.MachineTokenStore (legacy stores) for the revoked-at check,
// NOT output.IssuanceStore. The admin-side half of the round-trip is
// exactly what this test pins; the introspection half is covered
// separately in the broader E2E sweep.
func TestAdmin_Issuances_RevokeReflectsAtAdminGet(t *testing.T) {
	f := newIssuanceFlowFixture(t, "revoke-reflect")
	iss := f.mintIssuance(t)

	resp := f.h.AdminRequest("DELETE", "/admin/issuances/"+iss.ID, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke status: %d", resp.StatusCode)
	}

	post := getIssuanceByID(t, f.h, iss.ID)
	if post.RevokedAt == nil {
		t.Error("expected revoked_at populated after admin DELETE")
	}
}

// --- per-grant-type emit coverage --------------------------------
//
// Each test below drives one grant type end-to-end and asserts that an
// issuance row is visible via /admin/issuances within the default 24h
// window. Pre-, only token-exchange consistently emitted; the four
// standard grants below either dropped rows silently or had no insert at
// all in the case of client_credentials and jwt-bearer. The harness fix
// (WithResourceRegistry + WithIssuanceAudit, see e2e/harness.go) plus the
// service changes in internal/services/{client_credentials,jwt_bearer}.go
// close that gap.

// TestAdmin_Issuances_AuthCode_EmitsIssuance verifies the auth-code grant
// writes its own issuance row distinct from the token-exchange row that
// downstream services typically also produce.
func TestAdmin_Issuances_AuthCode_EmitsIssuance(t *testing.T) {
	f := newIssuanceFlowFixture(t, "authcode-emit")

	mcpClient := e2e.NewMCPClient(t, f.h, f.rs, f.WebAppClientID, "http://localhost:9999/callback")
	tokens := mcpClient.FullFlow(f.Email, f.Password, "tools/echo", false)
	if tokens.AccessToken == "" {
		t.Fatal("expected access token from auth-code flow")
	}

	// One issuance row, attributed to (UserID, WebAppClientID, MCPResourceServer URI).
	rows := listIssuancesByQuery(t, f.h, "user="+f.UserID+"&client="+f.WebAppClientID)
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 auth-code issuance row for (user, web-app-client), got %d", len(rows))
	}
	if rows[0].BackendKind != "mint" {
		t.Errorf("backend_kind: got %q, want mint", rows[0].BackendKind)
	}
	if rows[0].JTI == "" {
		t.Error("expected JTI populated on Mint issuance row")
	}
}

// TestAdmin_Issuances_RefreshToken_EmitsIssuance verifies the
// refresh_token grant emits a separate issuance row from the original
// auth-code grant.
func TestAdmin_Issuances_RefreshToken_EmitsIssuance(t *testing.T) {
	f := newIssuanceFlowFixture(t, "refresh-emit")

	mcpClient := e2e.NewMCPClient(t, f.h, f.rs, f.WebAppClientID, "http://localhost:9999/callback")
	tokens := mcpClient.FullFlow(f.Email, f.Password, "tools/echo", false)
	if tokens.RefreshToken == "" {
		t.Fatal("expected refresh_token from auth-code flow")
	}

	preCount := len(listIssuancesByQuery(t, f.h, "user="+f.UserID+"&client="+f.WebAppClientID))

	refreshed := f.h.RefreshToken(tokens.RefreshToken, f.WebAppClientID)
	if refreshed.AccessToken == "" {
		t.Fatal("expected access token from refresh grant")
	}

	postRows := listIssuancesByQuery(t, f.h, "user="+f.UserID+"&client="+f.WebAppClientID)
	if len(postRows) <= preCount {
		t.Fatalf("expected refresh_token to add an issuance row; pre=%d post=%d", preCount, len(postRows))
	}
}

// TestAdmin_Issuances_ClientCredentials_EmitsIssuance verifies the
// client_credentials grant emits an issuance row (the missing emit path
// surfaced). subject_user_id is the client_id per
// RFC 9068 §2.2.
func TestAdmin_Issuances_ClientCredentials_EmitsIssuance(t *testing.T) {
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI:          true,
		EnableClientCredentials: true,
	}, []string{"tools/echo"})
	rs := servers[0]
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	clientID, clientSecret := h.AdminCreateConfidentialClient(
		"cc-emit", []string{"client_credentials"}, "tools/echo",
	)

	tr := h.ClientCredentialsExchange(clientID, clientSecret, "tools/echo", rs.URI)
	if tr.AccessToken == "" {
		t.Fatal("expected access token from client_credentials grant")
	}

	rows := listIssuancesByQuery(t, h, "client="+clientID)
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 client_credentials issuance row, got %d", len(rows))
	}
	row := rows[0]
	if row.SubjectUserID != clientID {
		t.Errorf("subject_user_id: got %q, want %q (RFC 9068 §2.2)", row.SubjectUserID, clientID)
	}
	if row.ClientID != clientID {
		t.Errorf("client_id: got %q, want %q", row.ClientID, clientID)
	}
	if row.BackendKind != "mint" {
		t.Errorf("backend_kind: got %q, want mint", row.BackendKind)
	}
	if row.JTI == "" {
		t.Error("expected JTI populated on Mint issuance row")
	}
}

// TestAdmin_Issuances_JWTBearer_EmitsIssuance verifies the jwt-bearer
// (XAA) grant emits an issuance row. The subject is the mapped sub
// (auto-map mode → iss:sub composite).
func TestAdmin_Issuances_JWTBearer_EmitsIssuance(t *testing.T) {
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI: true,
		EnableXAA:      true,
	}, []string{"tools/echo"})
	rs := servers[0]
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	mockIdP := e2e.NewMockIdP(t)
	idpID := h.RegisterTrustedIDPSimple(
		" Test IdP",
		mockIdP.Issuer,
		mockIdP.Issuer+"/.well-known/jwks.json",
	)
	h.CreateXAAPolicySimple("Allow All", idpID)

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"tools/echo",
	)

	assertion := mockIdP.SignIDJAGWithResource(t, h.Issuer, clientID, "alice@testcorp.com", "tools/echo", rs.URI)
	tr := h.JWTBearerExchangeWithResource(clientID, clientSecret, assertion, "tools/echo", rs.URI)
	if tr.AccessToken == "" {
		t.Fatal("expected access token from jwt-bearer grant")
	}

	rows := listIssuancesByQuery(t, h, "client="+clientID)
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 jwt-bearer issuance row, got %d", len(rows))
	}
	row := rows[0]
	if row.ClientID != clientID {
		t.Errorf("client_id: got %q, want %q", row.ClientID, clientID)
	}
	if row.SubjectUserID == "" {
		t.Error("subject_user_id must be populated (the mapped sub)")
	}
	if row.BackendKind != "mint" {
		t.Errorf("backend_kind: got %q, want mint", row.BackendKind)
	}
}

// TestAdmin_Issuances_CombinedFiltersNarrow verifies the relaxed filter
// contract: combinations of user / client / resource narrow the result
// to rows matching every supplied dimension.
func TestAdmin_Issuances_CombinedFiltersNarrow(t *testing.T) {
	f := newIssuanceFlowFixture(t, "combined-filter")
	// mintIssuance produces two rows: one for the auth-code grant
	// (resource = MCPResourceServer URI) and one for the subsequent
	// token-exchange (resource = mcpResourceSlug). The token-exchange
	// row is the one whose client_id is f.MCPClientID — use that pair to
	// pin the post-filter behavior.
	tx := f.mintIssuance(t)

	// (user, client) alone — should return only the token-exchange row.
	rows := listIssuancesByQuery(t, f.h,
		"user="+f.UserID+"&client="+f.MCPClientID)
	if len(rows) != 1 {
		t.Fatalf("(user, client): got %d rows, want 1", len(rows))
	}
	if rows[0].ID != tx.ID {
		t.Errorf("(user, client): got id=%q, want %q", rows[0].ID, tx.ID)
	}

	// (user, client, resource) — same row, more dimensions.
	rows = listIssuancesByQuery(t, f.h,
		"user="+f.UserID+
			"&client="+f.MCPClientID+
			"&resource="+tx.ResourceID)
	if len(rows) != 1 {
		t.Fatalf("(user, client, resource): got %d rows, want 1", len(rows))
	}

	// (user, client) with a mismatched resource — should return 0.
	rows = listIssuancesByQuery(t, f.h,
		"user="+f.UserID+
			"&client="+f.MCPClientID+
			"&resource=does-not-exist")
	if len(rows) != 0 {
		t.Fatalf("(user, client, wrong-resource): got %d rows, want 0", len(rows))
	}

	// resource alone — should return only rows for that resource.
	rows = listIssuancesByQuery(t, f.h, "resource="+tx.ResourceID)
	if len(rows) != 1 {
		t.Fatalf("resource alone: got %d rows, want 1", len(rows))
	}
}
