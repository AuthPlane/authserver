//go:build e2e

package scenarios

import (
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// The per-client scope value is a ceiling for every grant alike. These cover it
// on the authorization_code path, end to end through the public HTTP surface:
// the admin API sets the ceiling, /oauth/authorize enforces it, and the token
// that comes out can never carry more than the client was registered for.

// TestClientScopeCeilingRejectsScopeOutsideCeiling asks for a scope that exists
// in the resource catalog but sits outside the client's ceiling. The catalog
// alone would admit it; the ceiling must not.
func TestClientScopeCeilingRejectsScopeOutsideCeiling(t *testing.T) {
	scopes := []string{"tools/echo", "tools/db_query"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{EnableAdminAPI: true}, scopes)
	rs := servers[0]

	const email, password = "alice@example.com", "password123"
	h.CreateUser(email, password)
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")
	h.RegisterScope(rs.URI, "tools/db_query", "Database query tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := h.AdminCreatePublicClient(
		"ceiling webapp",
		[]string{"authorization_code"},
		"tools/echo",
		[]string{redirectURI},
	)

	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)
	_, challenge := client.GeneratePKCE()
	params := client.BuildAuthorizeParams("tools/db_query", rs.URI, challenge, "test-state")

	// The ceiling is checked before the login/consent decision, so the request
	// dies on the first call: a user is never made to authenticate for a
	// request that cannot succeed no matter what they approve.
	result := h.Authorize(client.HTTPClient, params)
	if result.Error != "invalid_scope" {
		t.Fatalf("error = %q (description %q), want invalid_scope; the ceiling was not enforced",
			result.Error, result.ErrorDescription)
	}
	if result.NeedsLogin {
		t.Fatal("prompted for login on an out-of-ceiling request that can never succeed")
	}
	if result.NeedsConsent {
		t.Fatal("reached consent for an out-of-ceiling scope: the user must never be " +
			"asked to approve something the client cannot be granted")
	}
}

// TestClientScopeCeilingAllowsScopeWithinCeiling is the companion: the same
// setup, asking for something inside the ceiling, must still work. Guards
// against a fix that simply denies everything.
func TestClientScopeCeilingAllowsScopeWithinCeiling(t *testing.T) {
	scopes := []string{"tools/echo", "tools/db_query"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{EnableAdminAPI: true}, scopes)
	rs := servers[0]

	const email, password = "bob@example.com", "password123"
	h.CreateUser(email, password)
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")
	h.RegisterScope(rs.URI, "tools/db_query", "Database query tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := h.AdminCreatePublicClient(
		"within-ceiling webapp",
		[]string{"authorization_code"},
		"tools/echo tools/db_query",
		[]string{redirectURI},
	)

	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)
	tokens := client.FullFlow(email, password, "tools/echo", false)

	if got := strings.Fields(tokens.Scope); len(got) != 1 || got[0] != "tools/echo" {
		t.Fatalf("token scope = %q, want %q", tokens.Scope, "tools/echo")
	}
}

// TestAbsentScopeDefaultsToCeilingNotCatalog covers the compounding case. With
// scope omitted the server substitutes a default; that default must be bounded
// by the client's ceiling rather than being the resource's whole catalog.
func TestAbsentScopeDefaultsToCeilingNotCatalog(t *testing.T) {
	scopes := []string{"tools/echo", "tools/db_query"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{EnableAdminAPI: true}, scopes)
	rs := servers[0]

	const email, password = "carol@example.com", "password123"
	h.CreateUser(email, password)
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")
	h.RegisterScope(rs.URI, "tools/db_query", "Database query tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := h.AdminCreatePublicClient(
		"absent-scope webapp",
		[]string{"authorization_code"},
		"tools/echo",
		[]string{redirectURI},
	)

	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)
	verifier, challenge := client.GeneratePKCE()
	params := client.BuildAuthorizeParams("", rs.URI, challenge, "test-state")

	result := h.Authorize(client.HTTPClient, params)
	if !result.NeedsLogin {
		t.Fatal("expected login redirect")
	}
	h.Login(client.HTTPClient, email, password, extractRedirectParam(result.Location))

	result = h.Authorize(client.HTTPClient, params)
	if !result.NeedsConsent {
		t.Fatalf("expected consent redirect, got %+v", result)
	}

	// Approving the whole catalog must now fail the subset check in consent:
	// the session was seeded with the ceiling, not the catalog.
	resp := h.PostConsentRaw(client.HTTPClient, result.SessionID,
		[]string{"tools/echo", "tools/db_query"})
	resp.Body.Close()
	if resp.StatusCode < 400 {
		t.Fatalf("consent accepted the full catalog (status %d); the defaulted scope "+
			"was not bounded by the client ceiling", resp.StatusCode)
	}

	// Approving the ceiling itself succeeds and yields exactly the ceiling.
	code := h.GrantConsent(client.HTTPClient, result.SessionID, []string{"tools/echo"}, false)
	tokens := h.ExchangeCode(code, verifier, clientID, redirectURI)
	if got := strings.Fields(tokens.Scope); len(got) != 1 || got[0] != "tools/echo" {
		t.Fatalf("token scope = %q, want %q", tokens.Scope, "tools/echo")
	}
}

// TestDCRClientReceivesDefaultCeiling pins the other half of the change: a
// client that registers dynamically cannot state a ceiling, so the server
// assigns oauth.default_client_scope. Without that assignment the ceiling rule
// would deny every dynamically registered client.
func TestDCRClientReceivesDefaultCeiling(t *testing.T) {
	scopes := []string{"tools/echo", "tools/db_query"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		DefaultClientScope: "tools/echo",
	}, scopes)
	rs := servers[0]

	const email, password = "dave@example.com", "password123"
	h.CreateUser(email, password)
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")
	h.RegisterScope(rs.URI, "tools/db_query", "Database query tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)

	// Within the assigned ceiling: the full flow still works.
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)
	tokens := client.FullFlow(email, password, "tools/echo", false)
	if got := strings.Fields(tokens.Scope); len(got) != 1 || got[0] != "tools/echo" {
		t.Fatalf("token scope = %q, want %q", tokens.Scope, "tools/echo")
	}

	// Outside it: the assigned ceiling binds a DCR client the same as any other.
	other := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)
	_, challenge := other.GeneratePKCE()
	params := other.BuildAuthorizeParams("tools/db_query", rs.URI, challenge, "s")
	result := h.Authorize(other.HTTPClient, params)
	if result.Error != "invalid_scope" {
		t.Fatalf("error = %q, want invalid_scope for a DCR client exceeding its assigned ceiling",
			result.Error)
	}
}

// TestClientScopeCeilingEnforcedWithoutResource pins the compounding gap: the
// catalog check needs a resource to check against, but the client's own ceiling
// must apply whether or not resource= is present.
func TestClientScopeCeilingEnforcedWithoutResource(t *testing.T) {
	scopes := []string{"tools/echo", "tools/db_query"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{EnableAdminAPI: true}, scopes)
	rs := servers[0]

	const email, password = "erin@example.com", "password123"
	h.CreateUser(email, password)
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")
	h.RegisterScope(rs.URI, "tools/db_query", "Database query tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := h.AdminCreatePublicClient(
		"no-resource webapp",
		[]string{"authorization_code"},
		"tools/echo",
		[]string{redirectURI},
	)

	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)
	_, challenge := client.GeneratePKCE()
	// resource omitted — the catalog check is skipped, the ceiling must not be.
	params := client.BuildAuthorizeParams("tools/db_query", "", challenge, "test-state")

	result := h.Authorize(client.HTTPClient, params)
	if result.Error != "invalid_scope" {
		t.Fatalf("error = %q, want invalid_scope; without resource= the ceiling was skipped",
			result.Error)
	}
}

// TestConsentCannotWidenBeyondCeiling closes the loop from the other side: even
// a consent POST hand-crafted to approve more than was requested is refused.
func TestConsentCannotWidenBeyondCeiling(t *testing.T) {
	scopes := []string{"tools/echo", "tools/db_query"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{EnableAdminAPI: true}, scopes)
	rs := servers[0]

	const email, password = "frank@example.com", "password123"
	h.CreateUser(email, password)
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")
	h.RegisterScope(rs.URI, "tools/db_query", "Database query tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := h.AdminCreatePublicClient(
		"widening webapp",
		[]string{"authorization_code"},
		"tools/echo",
		[]string{redirectURI},
	)

	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)
	_, challenge := client.GeneratePKCE()
	params := client.BuildAuthorizeParams("tools/echo", rs.URI, challenge, "test-state")

	result := h.Authorize(client.HTTPClient, params)
	if !result.NeedsLogin {
		t.Fatal("expected login redirect")
	}
	h.Login(client.HTTPClient, email, password, extractRedirectParam(result.Location))

	result = h.Authorize(client.HTTPClient, params)
	if !result.NeedsConsent {
		t.Fatalf("expected consent redirect, got %+v", result)
	}

	resp := h.PostConsentRaw(client.HTTPClient, result.SessionID,
		[]string{"tools/echo", "tools/db_query"})
	resp.Body.Close()
	if resp.StatusCode < 400 {
		t.Fatalf("consent approved a scope outside both the request and the ceiling (status %d)",
			resp.StatusCode)
	}

	// And the legitimate path still works.
	sorted := []string{"tools/echo"}
	sort.Strings(sorted)
	code := h.GrantConsent(client.HTTPClient, result.SessionID, sorted, false)
	if code == "" {
		t.Fatal("expected an auth code after approving within the ceiling")
	}
}

// TestNoCeilingIsNotEnforcedYet covers the deprecation window. Every client
// registered before oauth.default_client_scope existed carries no ceiling —
// including every client ever created through DCR or CIMD, since neither door
// lets a client state one. Enforcing an absent ceiling as a ceiling of zero
// would deny all of them, so for now it is left unenforced and the request is
// bounded by the resource catalog alone, exactly as it was before ceilings
// reached this path.
//
// This is the behavior v0.3.0 reverses. When it does, this test should assert
// invalid_scope instead of a token — it is the canary for that change, not an
// endorsement of the current answer.
func TestNoCeilingIsNotEnforcedYet(t *testing.T) {
	scopes := []string{"tools/echo", "tools/db_query"}
	// No DefaultClientScope: the deployment has not opted in, so the client the
	// DCR door creates gets no ceiling.
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	const email, password = "erin@example.com", "password123"
	h.CreateUser(email, password)
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")
	h.RegisterScope(rs.URI, "tools/db_query", "Database query tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)

	// The full flow completes, and the token carries what the catalog allows.
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)
	tokens := client.FullFlow(email, password, "tools/db_query", false)
	if got := strings.Fields(tokens.Scope); len(got) != 1 || got[0] != "tools/db_query" {
		t.Fatalf("token scope = %q, want %q: a client with no ceiling must still "+
			"reach a token during the deprecation window", tokens.Scope, "tools/db_query")
	}

	// The catalog still bounds it — "no ceiling" is not "no checks".
	other := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)
	_, challenge := other.GeneratePKCE()
	params := other.BuildAuthorizeParams("tools/not_in_catalog", rs.URI, challenge, "s")
	if result := h.Authorize(other.HTTPClient, params); result.Error != "invalid_scope" {
		t.Fatalf("error = %q, want invalid_scope for a scope outside the catalog",
			result.Error)
	}
}

// TestDisjointCeilingAndCatalogFailsBeforeLogin covers the case where a client
// has a ceiling, omits scope, and the resource it points at declares nothing
// the ceiling allows — two resources on one server, and the client aimed at
// the wrong one.
//
// The defaulted set is then empty, and an empty set is a subset of every
// ceiling, so the subset check cannot catch it. Left alone the request reaches
// login, the user authenticates, and consent renders zero checkboxes and
// refuses every submit — the user has spent their password on a request that
// could never succeed. It has to fail at /authorize instead.
func TestDisjointCeilingAndCatalogFailsBeforeLogin(t *testing.T) {
	scopes := []string{"calendar/read"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		// The ceiling names a scope this resource does not declare.
		DefaultClientScope: "tools/echo",
	}, scopes)
	rs := servers[0]

	const email, password = "frank@example.com", "password123"
	h.CreateUser(email, password)
	h.RegisterScope(rs.URI, "calendar/read", "Read the calendar")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)

	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)
	_, challenge := client.GeneratePKCE()
	// No scope: the ADR-012 default applies, and ceiling ∩ catalog is empty.
	params := client.BuildAuthorizeParams("", rs.URI, challenge, "test-state")

	result := h.Authorize(client.HTTPClient, params)
	if result.Error != "invalid_scope" {
		t.Fatalf("error = %q (description %q), want invalid_scope when the ceiling and "+
			"the resource catalog do not overlap", result.Error, result.ErrorDescription)
	}
	if result.NeedsLogin {
		t.Fatal("prompted for login on a request that can never succeed: the user would " +
			"authenticate and then face a consent screen with no scopes to approve")
	}
	if result.NeedsConsent {
		t.Fatal("reached consent with nothing to approve")
	}
}

// TestNarrowedCeilingBindsRefreshToken is the narrowed-ceiling reproduction over the
// wire. A family granted two scopes is refreshed after the operator narrows
// the client to one: the refresh comes back narrowed rather than minting the
// stale pair, and an explicit request for the old pair is refused with the
// ceiling named, without spending the refresh token.
func TestNarrowedCeilingBindsRefreshToken(t *testing.T) {
	scopes := []string{"tools/echo", "tools/db_query"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{EnableAdminAPI: true}, scopes)
	rs := servers[0]

	const email, password = "bob@example.com", "password123"
	h.CreateUser(email, password)
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")
	h.RegisterScope(rs.URI, "tools/db_query", "Database query tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := h.AdminCreatePublicClient(
		"narrowed-later webapp",
		[]string{"authorization_code", "refresh_token"},
		"tools/echo tools/db_query",
		[]string{redirectURI},
	)

	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)
	tokens := client.FullFlow(email, password, "tools/echo tools/db_query", false)
	if got := strings.Fields(tokens.Scope); len(got) != 2 {
		t.Fatalf("precondition: token scope = %q, want both scopes", tokens.Scope)
	}
	if tokens.RefreshToken == "" {
		t.Fatal("precondition: expected a refresh token")
	}

	// The operator narrows the ceiling after the family exists.
	resp := h.AdminRequest(http.MethodPatch, "/admin/clients/"+clientID, map[string]any{
		"scope": "tools/echo",
	})
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH /admin/clients/%s: expected 200, got %d, body: %s", clientID, resp.StatusCode, raw)
	}

	// 1. Asking for the old pair is refused by the ceiling, and the refusal
	// says so rather than hiding behind the generic invalid_scope text.
	oe := h.RefreshTokenWithScopeExpectError(tokens.RefreshToken, clientID, "tools/echo tools/db_query")
	if oe.Error != "invalid_scope" {
		t.Fatalf("explicit refresh outside the ceiling: error = %q, want invalid_scope", oe.Error)
	}
	if !strings.Contains(oe.ErrorDescription, "registered scopes") {
		t.Fatalf("error_description should name the ceiling, got %q", oe.ErrorDescription)
	}

	// 2. The refusal did not spend the token: a plain refresh still works, and
	// comes back narrowed to what the ceiling leaves.
	refreshed := h.RefreshToken(tokens.RefreshToken, clientID)
	if got := strings.Fields(refreshed.Scope); len(got) != 1 || got[0] != "tools/echo" {
		t.Fatalf("refreshed scope = %q, want %q", refreshed.Scope, "tools/echo")
	}

	// 3. The rotated token stays bounded: the ceiling is read on every refresh.
	again := h.RefreshToken(refreshed.RefreshToken, clientID)
	if got := strings.Fields(again.Scope); len(got) != 1 || got[0] != "tools/echo" {
		t.Fatalf("second refresh scope = %q, want %q", again.Scope, "tools/echo")
	}
}
