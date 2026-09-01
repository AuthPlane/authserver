//go:build e2e

package scenarios

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/e2e"
)

// consentGrantView mirrors the relevant subset of the
// /admin/users/{id}/grants response shape (see internal/admin/dto.
// ConsentGrantView). The harness deliberately does not import the DTO
// package — only the fields the assertions actually inspect are listed
// here. RevokedAt is a pointer so absence-on-active-rows decodes to nil.
type consentGrantView struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	ClientID   string     `json:"client_id"`
	ResourceID string     `json:"resource_id"`
	Scopes     []string   `json:"scopes"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

type userGrantsView struct {
	ConsentGrants []consentGrantView `json:"consent_grants"`
	BrokerGrants  []json.RawMessage  `json:"broker_grants"`
}

// findActiveConsentGrants reads /admin/users/{id}/grants and returns
// every consent_grants row matching (clientID, resourceID) with
// revoked_at == nil. The admin surface returns full history so callers
// must filter; forbade direct ConsentGrantStore.Get reads from
// e2e.
func findActiveConsentGrants(t *testing.T, h *e2e.TestHarness, userID, clientID, resourceID string) []consentGrantView {
	t.Helper()
	resp := h.AdminRequest("GET", "/admin/users/"+url.PathEscape(userID)+"/grants", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /admin/users/%s/grants: status %d, body %s", userID, resp.StatusCode, string(raw))
	}
	var got userGrantsView
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode user grants: %v", err)
	}
	var matches []consentGrantView
	for _, g := range got.ConsentGrants {
		if g.ClientID == clientID && g.ResourceID == resourceID && g.RevokedAt == nil {
			matches = append(matches, g)
		}
	}
	return matches
}

// TestPerMCPConsent_FullLifecycle exercises  end-to-end:
//
//   - GET /oauth/authorize?response_type=code&client_id=…&resource=tasks-mcp
//     &scope=tasks:summarize+tasks:list&state=…
//     → 302 to /consent?session_id=…
//   - GET /consent → renders the per-MCP screen — the harness's
//     RunFlowC1Consent helper handles that.
//   - POST /consent action=allow scopes=tasks:summarize scopes=tasks:list
//     → 302 to the agent's redirect_uri with ?code=…
//   - POST /oauth/token grant_type=authorization_code → JWT with
//     aud=<resource URI>, scope="tasks:summarize tasks:list"
//   - DB-side assertion: a row exists in the unified consent_grants table
//     keyed on (user, agent client, resource_id) with the requested
//     scopes — confirming the now store binding (the legacy
//     consent_grants table is gone; there is no parallel-write to assert).
//     The assertion is now driven through the public admin API
//
// (GET /admin/users/{id}/grants) per — direct ConsentGrantStore
//
//	access from e2e is forbidden.
//
// Sub-tests cover the deny path, scope-narrowing, and the broker-resource
// rejection flavour ( ErrConsentResourceNotMint → 400 Invalid
// Resource HTML page).
func TestPerMCPConsent_FullLifecycle(t *testing.T) {
	scopes := []string{"tasks:summarize", "tasks:list"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI: true,
	}, scopes)
	rs := servers[0]

	h.RegisterScope(rs.URI, "tasks:summarize", "Summarise the user's tasks")
	h.RegisterScope(rs.URI, "tasks:list", "List the user's tasks")

	const email = "alice-permcp@example.com"
	const password = "pass123"
	userID := h.CreateUser(email, password)

	// Register the agent client as a public client (PKCE only, no
	// client_secret) so MCPClient.ExchangeCode at /oauth/token works
	// without secret authentication. client_id auto-generated.
	redirectURI := "http://localhost:9999/callback"
	agentClientID := h.AdminCreatePublicClient(
		"per-mcp-consent agent",
		[]string{"authorization_code"},
		strings.Join(scopes, " "),
		[]string{redirectURI},
	)

	// Resolve the resource id — required for the DB-side assertion
	// below. SetupE2E names the first resource server "mcp-0". Lookup
	// goes through the public admin API;
	// the Gate-0 shortcut h.ResourceStore().GetBySlug is gone.
	mintRes := h.AdminGetResourceBySlug("mcp-0")

	// --- 1. Happy path — alice approves both scopes. Exchange the code
	// and assert the JWT carries scope=<approved> and aud=<resource URI>.
	t.Run("ApproveAll", func(t *testing.T) {
		code, verifier, _ := h.RunFlowC1Consent(email, password, agentClientID, redirectURI, mintRes.Slug, scopes, scopes)
		if code == "" {
			t.Fatal("RunFlowC1Consent returned empty code on approve path")
		}

		tokens := h.ExchangeCode(code, verifier, agentClientID, redirectURI)
		if tokens.AccessToken == "" {
			t.Fatal("auth-code redemption returned empty access_token after consent approve")
		}
		// JWT scope claim equals the approved set (order-insensitive).
		gotScope := strings.Fields(tokens.Scope)
		sort.Strings(gotScope)
		wantScope := append([]string(nil), scopes...)
		sort.Strings(wantScope)
		if !reflect.DeepEqual(gotScope, wantScope) {
			t.Errorf("token response scope = %v, want %v", gotScope, wantScope)
		}
		// aud claim must be the resource URI.
		claims := parseJWTClaims(t, tokens.AccessToken)
		audClaim, _ := claims["aud"].(string)
		if audClaim == "" {
			// aud may be []any in the multi-aud case — normalise.
			if list, ok := claims["aud"].([]any); ok && len(list) > 0 {
				audClaim, _ = list[0].(string)
			}
		}
		if audClaim != rs.URI {
			t.Errorf("JWT aud = %q, want %q", audClaim, rs.URI)
		}

		// Persisted consent_grants row carries the same scopes against
		// the renamed- table (load-bearing for the wiring
		// regression that motivated ). Read via the public admin
		// API.Get).
		grants := findActiveConsentGrants(t, h, userID, agentClientID, mintRes.ID)
		if len(grants) != 1 {
			t.Fatalf("expected exactly one active consent grant after approve, got %d", len(grants))
		}
		grant := grants[0]
		gotGrantScopes := append([]string(nil), grant.Scopes...)
		sort.Strings(gotGrantScopes)
		if !reflect.DeepEqual(gotGrantScopes, wantScope) {
			t.Errorf("consent grant scopes = %v, want %v", gotGrantScopes, wantScope)
		}
		if grant.ResourceID != mintRes.ID {
			t.Errorf("consent grant resource_id = %q, want %q", grant.ResourceID, mintRes.ID)
		}
		if grant.UserID != userID || grant.ClientID != agentClientID {
			t.Errorf("consent grant identity tuple wrong: user=%q client=%q", grant.UserID, grant.ClientID)
		}
	})

	// --- 2. Scope narrowing — alice approves only one scope. JWT must
	// reflect the narrowed set.
	t.Run("ScopeNarrowingByApprovedSubset", func(t *testing.T) {
		const narrowEmail = "alice-narrow@example.com"
		const narrowPassword = "pass123"
		narrowUserID := h.CreateUser(narrowEmail, narrowPassword)

		approved := []string{"tasks:summarize"}
		code, verifier, _ := h.RunFlowC1Consent(
			narrowEmail, narrowPassword, agentClientID, redirectURI, mintRes.Slug,
			scopes,   // requested both
			approved, // approved only summarize
		)
		if code == "" {
			t.Fatal("RunFlowC1Consent returned empty code on narrow path")
		}

		tokens := h.ExchangeCode(code, verifier, agentClientID, redirectURI)
		gotScope := strings.Fields(tokens.Scope)
		sort.Strings(gotScope)
		if !reflect.DeepEqual(gotScope, approved) {
			t.Errorf("narrowed token response scope = %v, want %v", gotScope, approved)
		}

		grants := findActiveConsentGrants(t, h, narrowUserID, agentClientID, mintRes.ID)
		if len(grants) != 1 {
			t.Fatalf("expected exactly one active consent grant after narrow approve, got %d", len(grants))
		}
		if !reflect.DeepEqual(grants[0].Scopes, approved) {
			t.Errorf("narrowed consent scopes = %v, want %v", grants[0].Scopes, approved)
		}
	})

	// --- 3. Deny — alice rejects.
	t.Run("DenyConsent_NoGrantRowWritten", func(t *testing.T) {
		const denyEmail = "alice-deny@example.com"
		const denyPassword = "pass123"
		denyUserID := h.CreateUser(denyEmail, denyPassword)

		// Pass approvedScopes=nil to take the deny branch.
		code, _, _ := h.RunFlowC1Consent(
			denyEmail, denyPassword, agentClientID, redirectURI, mintRes.Slug,
			scopes, nil,
		)
		if code != "" {
			t.Fatalf("deny path should not return a code, got %q", code)
		}

		// "Consent denied" semantics: a denied flow may produce no row
		// at all OR a row whose revoked_at is set. Either way, no
		// active grant should be visible against the (user, client,
		// resource) tuple.
		grants := findActiveConsentGrants(t, h, denyUserID, agentClientID, mintRes.ID)
		if len(grants) != 0 {
			t.Errorf("expected no active consent grant rows after deny, got %d: %+v", len(grants), grants)
		}
	})

	// --- 4. Broker resource on /authorize → 400 Invalid Resource HTML.
	t.Run("BrokerResourceRejected_400InvalidResource", func(t *testing.T) {
		// Seed a BrokerProvider + Broker resource via the public admin
		// API so we can hit /authorize with the broker slug. The
		// provider is never invoked (the test exercises an /authorize
		// rejection BEFORE the brokerproto adapter runs), so the fake
		// URLs are fine.
		h.AdminCreateBrokerProvider(e2e.CreateBrokerProviderSpec{
			Slug:        "stub-prov-rejected",
			DisplayName: "stub-prov-rejected",
			Protocol:    "oauth",
			ConfigData: map[string]any{
				"client_id":         "stub",
				"client_secret_ref": "CONNECTOR_E2E_MOCK_SECRET",
				"authorize_url":     "http://stub/authorize",
				"token_url":         "http://stub/token",
				"response_format":   "standard",
			},
		})
		const brokerSlug = "broker-rejected"
		h.AdminCreateResource(e2e.CreateResourceSpec{
			Slug:               brokerSlug,
			URI:                "https://" + brokerSlug + ".test",
			BackendKind:        "broker",
			BrokerProviderSlug: "stub-prov-rejected",
			DisplayName:        brokerSlug,
		})

		client := h.NewClient()

		// Broker resource is rejected at /authorize before any code
		// redemption — only the challenge is needed for the request
		// shape; the verifier doesn't matter on this path. PKCE S256:
		// verifier is any 43..128 char URL-safe random string;
		// challenge is base64url(sha256(verifier)) without padding.
		// Inlined here (was internal/crypto.{GenerateVerifier,
		// ComputeS256Challenge} before forbade internal/ imports
		// from e2e).
		const verifier = "test-verifier-per-mcp-consent-broker-rejected-43chars-12"
		hash := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(hash[:])
		params := url.Values{
			"response_type":         {"code"},
			"client_id":             {agentClientID},
			"redirect_uri":          {redirectURI},
			"scope":                 {"anything"},
			"resource":              {brokerSlug},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
			"state":                 {"xyz"},
		}

		// Login via the standard helper so the broker rejection happens
		// post-auth (the authorize service rejects the broker resource
		// before consent screen render).
		const brokerEmail = "alice-broker@example.com"
		const brokerPassword = "pass123"
		h.CreateUser(brokerEmail, brokerPassword)
		h.Login(client, brokerEmail, brokerPassword, "")

		resp, err := client.Get(h.Issuer + "/oauth/authorize?" + params.Encode())
		if err != nil {
			t.Fatalf("GET /oauth/authorize: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("broker resource on /authorize: status %d, want 400. body=%s", resp.StatusCode, body)
		}
		if !strings.Contains(string(body), "Invalid Resource") {
			t.Errorf("expected 'Invalid Resource' in body, got: %s", body)
		}
	})
}
