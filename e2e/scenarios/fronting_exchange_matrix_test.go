//go:build e2e

package scenarios

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// TestFrontingExchangeMatrix drives the fronted Mint->Mint token exchange
// through /oauth/token for every combination of scope_map shape x subject
// scope set x requested scope, and checks each response against an oracle
// written from the fronting specification — not from the server's helpers.
//
// Subject tokens are client_credentials tokens minted with resource=<gateway
// URI>, one client per subject scope set, the way a gateway integration
// obtains them. The exchanging gateway client authenticates with
// client_secret_post for every case, and additionally with
// client_secret_basic for every omitted-scope case: an omitted scope is the
// shape that once skipped the fronting link's scope_map, so it is exercised
// under both client authentication methods.
//
// Specification (Mint target). reverse(t) is the sorted list of source keys
// whose value list contains t; the source required for t is reverse(t)[0].
//   - scope omitted: D = { t : reverse(t)[0] in S }. D empty -> invalid_scope,
//     recorded as fronting_subject_scope_insufficient. Otherwise issued with
//     scope = D, and the token.exchanged audit row carries scopes=D.
//   - scope R given: a t with no reverse -> invalid_scope
//     (fronting_scope_unmapped); otherwise a t with reverse(t)[0] not in S ->
//     invalid_scope (fronting_subject_scope_insufficient); otherwise issued
//     with scope = R.
//
// Issued tokens carry aud = target URI, client_id = gateway slug and
// act.sub = gateway slug.
//
// The empty subject scope set is not reachable here — a client_credentials
// token always carries the client's scope — so the subject set {x} (a source
// scope no map entry names) stands in for "reaches nothing". The service
// matrix covers the literal empty set.
func TestFrontingExchangeMatrix(t *testing.T) {
	const (
		gwSlug  = "fxm-gw"
		apiSlug = "fxm-api"
		gwURI   = "https://fxm-gw.test"
		apiURI  = "https://fxm-api.test"

		subjectTokenType = "urn:ietf:params:oauth:token-type:access_token"
		exchangeGrant    = "urn:ietf:params:oauth:grant-type:token-exchange"
	)

	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI:             true,
		EnableTokenExchange:        true,
		EnableClientCredentials:    true,
		TokenExchangeMaxChainDepth: 5,
	}, []string{"placeholder"})

	// Exchanging gateway clients, one per client authentication method.
	// Created before the target resource: policy.exchange.allowed_client_ids
	// may only name clients that exist.
	postID, postSecret := fxmCreateExchanger(t, h, "fxm exchanger post", "client_secret_post")
	basicID, basicSecret := fxmCreateExchanger(t, h, "fxm exchanger basic", "client_secret_basic")

	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:        gwSlug,
		URI:         gwURI,
		BackendKind: "mint",
		DisplayName: "Matrix Gateway",
		Scopes:      []e2e.AdminScope{{Name: "a"}, {Name: "b"}, {Name: "x"}},
	})
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:        apiSlug,
		URI:         apiURI,
		BackendKind: "mint",
		DisplayName: "Matrix API",
		Scopes:      []e2e.AdminScope{{Name: "AA"}, {Name: "BB"}, {Name: "CC"}},
		Policy: &e2e.AdminPolicy{
			Exchange: e2e.AdminExchangePolicy{AllowedClientIDs: []string{postID, basicID}},
		},
	})

	// One subject token per non-empty subset of the gateway catalog.
	type subjectTok struct {
		scopes []string
		token  string
	}
	var subjects []subjectTok
	catalog := []string{"a", "b", "x"}
	for mask := 1; mask < 1<<len(catalog); mask++ {
		var s []string
		for i, k := range catalog {
			if mask&(1<<i) != 0 {
				s = append(s, k)
			}
		}
		scopeStr := strings.Join(s, " ")
		id, secret := h.AdminCreateConfidentialClient("fxm subject "+scopeStr, []string{"client_credentials"}, scopeStr)
		tr := h.ClientCredentialsExchange(id, secret, scopeStr, gwURI)
		claims := parseJWTClaims(t, tr.AccessToken)
		if got := audAsString(claims["aud"]); got != gwURI {
			t.Fatalf("subject token aud = %q, want %q", got, gwURI)
		}
		if got := stringClaim(claims, "scope"); got != scopeStr {
			t.Fatalf("subject token scope = %q, want %q", got, scopeStr)
		}
		subjects = append(subjects, subjectTok{scopes: s, token: tr.AccessToken})
	}

	maps := []struct {
		name string
		m    map[string][]string
	}{
		{"1to1", map[string][]string{"a": {"AA"}}},
		{"1toN", map[string][]string{"a": {"AA", "BB"}}},
		{"Nto1", map[string][]string{"a": {"AA"}, "b": {"AA"}}},
	}

	type authMethod struct {
		name, id, secret string
		basic            bool
	}
	post := authMethod{"post", postID, postSecret, false}
	basic := authMethod{"basic", basicID, basicSecret, true}

	total, issued := 0, 0
	for i, mp := range maps {
		if i > 0 {
			h.AdminDeleteFrontingLink(gwSlug, apiSlug)
		}
		h.AdminCreateFrontingLink(e2e.CreateFrontingLinkSpec{Source: gwSlug, Target: apiSlug, ScopeMap: mp.m})

		// Requests: omitted, each mapped target, and one catalog target
		// the map does not name.
		requests := [][]string{nil}
		for _, tg := range fxmAllTargets(mp.m) {
			requests = append(requests, []string{tg})
		}
		requests = append(requests, []string{"CC"})

		for _, subj := range subjects {
			for _, reqScopes := range requests {
				methods := []authMethod{post}
				if reqScopes == nil {
					methods = append(methods, basic)
				}
				for _, am := range methods {
					total++
					want := fxmOracleMint(mp.m, subj.scopes, reqScopes)
					if want.issued {
						issued++
					}
					label := "omitted"
					if reqScopes != nil {
						label = strings.Join(reqScopes, "+")
					}
					name := "map=" + mp.name + "/subject=" + strings.Join(subj.scopes, "+") + "/scope=" + label + "/auth=" + am.name
					t.Run(name, func(t *testing.T) {
						deniedBefore := fxmCountAudit(t, h, "token.exchange_denied", am.id, "reason="+want.reason)
						exchangedBefore := fxmCountAudit(t, h, "token.exchanged", am.id, "")

						status, body := fxmExchange(t, h, am.id, am.secret, am.basic, url.Values{
							"grant_type":         {exchangeGrant},
							"subject_token":      {subj.token},
							"subject_token_type": {subjectTokenType},
							"resource":           {apiURI},
						}, strings.Join(reqScopes, " "))

						if !want.issued {
							if status != http.StatusBadRequest {
								t.Fatalf("want 400 invalid_scope (%s), got %d: %v", want.reason, status, body)
							}
							if got, _ := body["error"].(string); got != "invalid_scope" {
								t.Errorf("error = %q, want invalid_scope", got)
							}
							if _, ok := body["access_token"]; ok {
								t.Errorf("refusal carried an access_token")
							}
							if got := fxmCountAudit(t, h, "token.exchange_denied", am.id, "reason="+want.reason); got != deniedBefore+1 {
								t.Errorf("token.exchange_denied rows with reason=%s: %d -> %d, want exactly one new", want.reason, deniedBefore, got)
							}
							if got := fxmCountAudit(t, h, "token.exchanged", am.id, ""); got != exchangedBefore {
								t.Errorf("refusal added %d token.exchanged rows", got-exchangedBefore)
							}
							return
						}

						wantScope := strings.Join(want.scopes, " ")
						if status != http.StatusOK {
							t.Fatalf("want 200 with scope %q, got %d: %v", wantScope, status, body)
						}
						accessToken, _ := body["access_token"].(string)
						claims := parseJWTClaims(t, accessToken)
						if got := stringClaim(claims, "scope"); got != wantScope {
							t.Errorf("token scope = %q, want %q", got, wantScope)
						}
						if got, _ := body["scope"].(string); got != wantScope {
							t.Errorf("response scope = %q, want %q", got, wantScope)
						}
						if got := audAsString(claims["aud"]); got != apiURI {
							t.Errorf("aud = %q, want %q", got, apiURI)
						}
						if got := stringClaim(claims, "client_id"); got != gwSlug {
							t.Errorf("client_id = %q, want %q", got, gwSlug)
						}
						act, _ := claims["act"].(map[string]any)
						if got, _ := act["sub"].(string); got != gwSlug {
							t.Errorf("act.sub = %v, want %q", act["sub"], gwSlug)
						}
						jti := stringClaim(claims, "jti")
						detail := fxmFindAudit(t, h, "token.exchanged", am.id, "jti="+jti+" ")
						if detail == "" {
							t.Fatalf("no token.exchanged audit row for jti=%s", jti)
						}
						gotAuditScopes := fxmDetailField(detail, "scopes", "chain_kind")
						if gotAuditScopes == "" {
							t.Errorf("token.exchanged audit row has an empty scopes=: %q", detail)
						}
						if gotAuditScopes != wantScope {
							t.Errorf("audit scopes = %q, want %q (detail %q)", gotAuditScopes, wantScope, detail)
						}
					})
				}
			}
		}
	}
	t.Logf("fronted exchange e2e matrix: %d combinations (%d issued, %d refused)", total, issued, total-issued)
}

// ---------------------------------------------------------------------------
// Oracle — the fronted Mint rules, from the specification.
// ---------------------------------------------------------------------------

type fxmOutcome struct {
	issued bool
	scopes []string // sorted, when issued
	reason string   // denial reason, when refused
}

func fxmContains(set []string, s string) bool {
	for _, v := range set {
		if v == s {
			return true
		}
	}
	return false
}

func fxmSourcesFor(m map[string][]string, target string) []string {
	var out []string
	for src, tgts := range m {
		if fxmContains(tgts, target) {
			out = append(out, src)
		}
	}
	sort.Strings(out)
	return out
}

func fxmAllTargets(m map[string][]string) []string {
	var out []string
	for _, tgts := range m {
		for _, tg := range tgts {
			if !fxmContains(out, tg) {
				out = append(out, tg)
			}
		}
	}
	sort.Strings(out)
	return out
}

// fxmOracleMint returns the expected outcome; requested == nil means the
// scope parameter is omitted.
func fxmOracleMint(m map[string][]string, subject, requested []string) fxmOutcome {
	if requested == nil {
		var derived []string
		for _, tg := range fxmAllTargets(m) {
			if fxmContains(subject, fxmSourcesFor(m, tg)[0]) {
				derived = append(derived, tg)
			}
		}
		if len(derived) == 0 {
			return fxmOutcome{reason: "fronting_subject_scope_insufficient"}
		}
		return fxmOutcome{issued: true, scopes: derived}
	}
	for _, tg := range requested {
		if len(fxmSourcesFor(m, tg)) == 0 {
			return fxmOutcome{reason: "fronting_scope_unmapped"}
		}
	}
	for _, tg := range requested {
		if !fxmContains(subject, fxmSourcesFor(m, tg)[0]) {
			return fxmOutcome{reason: "fronting_subject_scope_insufficient"}
		}
	}
	out := append([]string(nil), requested...)
	sort.Strings(out)
	return fxmOutcome{issued: true, scopes: out}
}

// ---------------------------------------------------------------------------
// HTTP + admin helpers.
// ---------------------------------------------------------------------------

// fxmCreateExchanger registers a confidential agent client holding the
// token-exchange grant with the given token_endpoint_auth_method.
func fxmCreateExchanger(t *testing.T, h *e2e.TestHarness, name, authMethod string) (string, string) {
	t.Helper()
	resp := h.AdminRequest("POST", "/admin/clients", map[string]any{
		"client_name":                name,
		"redirect_uris":              []string{"http://localhost:9999/callback"},
		"grant_types":                []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": authMethod,
		"scope":                      "AA BB CC",
		"agent":                      true,
		"agent_description":          name,
	})
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create exchanger %q: status %d, body %s", name, resp.StatusCode, raw)
	}
	var out struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.ClientID == "" || out.ClientSecret == "" {
		t.Fatalf("create exchanger %q: bad response %s (%v)", name, raw, err)
	}
	return out.ClientID, out.ClientSecret
}

// fxmExchange POSTs a token exchange to /oauth/token, authenticating with
// HTTP Basic (client_secret_basic) or form credentials (client_secret_post).
// An empty scope leaves the parameter out entirely.
func fxmExchange(t *testing.T, h *e2e.TestHarness, clientID, clientSecret string, basic bool, form url.Values, scope string) (int, map[string]any) {
	t.Helper()
	if scope != "" {
		form.Set("scope", scope)
	}
	if !basic {
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, h.Issuer+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		// RFC 6749 §2.3.1: id and secret are form-urlencoded before Basic.
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode token response (%d): %v: %s", resp.StatusCode, err, raw)
	}
	return resp.StatusCode, body
}

type fxmAuditRow struct {
	Action string `json:"action"`
	Detail string `json:"detail"`
}

func fxmAuditRows(t *testing.T, h *e2e.TestHarness, action, clientID string) []fxmAuditRow {
	t.Helper()
	q := url.Values{"action": {action}, "client_id": {clientID}, "limit": {"1000"}}
	resp := h.AdminRequest("GET", "/admin/audit?"+q.Encode(), nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/audit?%s: status %d", q.Encode(), resp.StatusCode)
	}
	var rows []fxmAuditRow
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		t.Fatalf("decode audit rows: %v", err)
	}
	return rows
}

// fxmCountAudit counts rows for (action, client) whose detail equals detail;
// an empty detail counts every row.
func fxmCountAudit(t *testing.T, h *e2e.TestHarness, action, clientID, detail string) int {
	t.Helper()
	n := 0
	for _, r := range fxmAuditRows(t, h, action, clientID) {
		if detail == "" || r.Detail == detail {
			n++
		}
	}
	return n
}

// fxmFindAudit returns the detail of the first row whose detail contains
// needle, or "".
func fxmFindAudit(t *testing.T, h *e2e.TestHarness, action, clientID, needle string) string {
	t.Helper()
	for _, r := range fxmAuditRows(t, h, action, clientID) {
		if strings.Contains(r.Detail, needle) {
			return r.Detail
		}
	}
	return ""
}

// fxmDetailField extracts key='s value from an audit detail. The value may
// contain spaces (a scope list), so it runs up to " <next>=".
func fxmDetailField(detail, key, next string) string {
	start := strings.Index(detail, key+"=")
	if start < 0 {
		return "<absent>"
	}
	rest := detail[start+len(key)+1:]
	if end := strings.Index(rest, " "+next+"="); end >= 0 {
		return rest[:end]
	}
	return rest
}
