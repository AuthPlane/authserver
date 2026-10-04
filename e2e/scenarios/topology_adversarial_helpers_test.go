//go:build e2e

package scenarios

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// Shared plumbing for the topology_<name>_adversarial_test.go files. Every
// helper here speaks the public HTTP surface (/oauth/*, /admin/*) and nothing
// else, so the scenarios exercise the same paths a deployment does.

const (
	topoGrantTE       = "urn:ietf:params:oauth:grant-type:token-exchange"
	topoGrantJWT      = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	topoTokenTypeAT   = "urn:ietf:params:oauth:token-type:access_token"
	topoRedirect      = "http://localhost:9999/callback"
	topoPassword      = "pass123"
	topoFindingPrefix = "FINDING"
)

// topoAuth is the client authentication method a request uses at the token
// endpoint (RFC 6749 §2.3.1).
type topoAuth int

const (
	topoAuthPost  topoAuth = iota // client_secret_post
	topoAuthBasic                 // client_secret_basic
	topoAuthNone                  // public client: client_id only
)

func (a topoAuth) String() string {
	switch a {
	case topoAuthBasic:
		return "client_secret_basic"
	case topoAuthNone:
		return "none"
	default:
		return "client_secret_post"
	}
}

// topoBothAuth is the pair every confidential-client scenario runs under.
var topoBothAuth = []topoAuth{topoAuthBasic, topoAuthPost}

// topoResp is a decoded token-endpoint response, success or error.
type topoResp struct {
	Status int
	Body   map[string]any
	Raw    string
}

func (r topoResp) str(k string) string { s, _ := r.Body[k].(string); return s }
func (r topoResp) Err() string         { return r.str("error") }
func (r topoResp) AccessToken() string { return r.str("access_token") }
func (r topoResp) Scope() string       { return r.str("scope") }
func (r topoResp) Refresh() string     { return r.str("refresh_token") }
func (r topoResp) OK() bool            { return r.Status == http.StatusOK && r.AccessToken() != "" }

// topoToken POSTs form to /oauth/token, authenticating as (id, secret) with
// the given method.
func topoToken(t *testing.T, h *e2e.TestHarness, form url.Values, auth topoAuth, id, secret string) topoResp {
	t.Helper()
	f := url.Values{}
	for k, v := range form {
		f[k] = append([]string(nil), v...)
	}
	req, err := http.NewRequest(http.MethodPost, h.Issuer+"/oauth/token", nil)
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}
	switch auth {
	case topoAuthBasic:
		req.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
	case topoAuthPost:
		f.Set("client_id", id)
		f.Set("client_secret", secret)
	case topoAuthNone:
		if id != "" {
			f.Set("client_id", id)
		}
	}
	req.Body = io.NopCloser(strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := topoResp{Status: resp.StatusCode, Raw: string(raw), Body: map[string]any{}}
	_ = json.Unmarshal(raw, &out.Body)
	return out
}

// topoExchangeForm builds an RFC 8693 request. Empty resource/scope are
// omitted, never sent empty.
func topoExchangeForm(subject, resource, scope string) url.Values {
	f := url.Values{
		"grant_type":         {topoGrantTE},
		"subject_token":      {subject},
		"subject_token_type": {topoTokenTypeAT},
	}
	if resource != "" {
		f.Set("resource", resource)
	}
	if scope != "" {
		f.Set("scope", scope)
	}
	return f
}

// topoCCForm builds a client_credentials request, omitting empty fields.
func topoCCForm(resource, scope string) url.Values {
	f := url.Values{"grant_type": {"client_credentials"}}
	if resource != "" {
		f.Set("resource", resource)
	}
	if scope != "" {
		f.Set("scope", scope)
	}
	return f
}

// topoPKCE returns an RFC 7636 S256 verifier/challenge pair.
func topoPKCE() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// topoAuthorizeParams builds /oauth/authorize params. Empty values are omitted
// so each test can drop exactly the parameter it is probing.
func topoAuthorizeParams(clientID, redirect, resource, scope, challenge, method string) url.Values {
	p := url.Values{"response_type": {"code"}, "client_id": {clientID}, "state": {"topo-state"}}
	for k, v := range map[string]string{
		"redirect_uri": redirect, "resource": resource, "scope": scope,
		"code_challenge": challenge, "code_challenge_method": method,
	} {
		if v != "" {
			p.Set(k, v)
		}
	}
	return p
}

// topoAuthorizeRaw GETs /oauth/authorize without following redirects.
func topoAuthorizeRaw(t *testing.T, h *e2e.TestHarness, c *http.Client, params url.Values) (int, string) {
	t.Helper()
	resp, err := c.Get(h.Issuer + "/oauth/authorize?" + params.Encode())
	if err != nil {
		t.Fatalf("GET /oauth/authorize: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location")
}

// topoLoggedIn returns a cookie-jar client with an authenticated session.
func topoLoggedIn(t *testing.T, h *e2e.TestHarness, email string) *http.Client {
	t.Helper()
	c := h.NewClient()
	h.Login(c, email, topoPassword, "")
	return c
}

// topoCodeFor walks /authorize → /consent for params with a logged-in user
// and returns the code. approve lists the scopes ticked on the consent screen;
// nil approves whatever the screen offered (the defaulted scope, when the
// request omitted it).
func topoCodeFor(t *testing.T, h *e2e.TestHarness, c *http.Client, params url.Values, approve []string) string {
	t.Helper()
	res := h.Authorize(c, params)
	if res.Error != "" {
		t.Fatalf("authorize refused: %s (%s)", res.Error, res.ErrorDescription)
	}
	if res.Code != "" {
		return res.Code
	}
	if !res.NeedsConsent {
		t.Fatalf("authorize: expected consent or code, got %+v", res)
	}
	if approve == nil {
		approve = topoConsentOffered(t, h, c, res.SessionID)
	}
	return h.GrantConsent(c, res.SessionID, approve, false)
}

// topoConsentOffered scrapes the scope checkboxes the consent screen renders.
func topoConsentOffered(t *testing.T, h *e2e.TestHarness, c *http.Client, sessionID string) []string {
	t.Helper()
	resp, err := c.Get(h.Issuer + "/consent?session_id=" + url.QueryEscape(sessionID))
	if err != nil {
		t.Fatalf("GET /consent: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out []string
	for _, chunk := range strings.Split(string(body), `name="scopes"`)[1:] {
		i := strings.Index(chunk, `value="`)
		if i < 0 {
			continue
		}
		rest := chunk[i+len(`value="`):]
		if j := strings.Index(rest, `"`); j > 0 {
			out = append(out, rest[:j])
		}
	}
	return out
}

// topoRedeem redeems a code for a public client (PKCE only).
func topoRedeem(t *testing.T, h *e2e.TestHarness, code, verifier, clientID string) topoResp {
	t.Helper()
	return topoToken(t, h, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {topoRedirect}, "code_verifier": {verifier},
	}, topoAuthNone, clientID, "")
}

// topoUserToken drives the documented auth-code flow for a public client and
// returns the redeemed token response.
func topoUserToken(t *testing.T, h *e2e.TestHarness, email, clientID, resource string, scopes []string) topoResp {
	t.Helper()
	code, verifier, _ := h.RunFlowC1Consent(email, topoPassword, clientID, topoRedirect, resource, scopes, scopes)
	r := topoRedeem(t, h, code, verifier, clientID)
	if !r.OK() {
		t.Fatalf("precondition: redeem code for %s at %s: %d %s", clientID, resource, r.Status, r.Raw)
	}
	return r
}

// topoCreateClient registers a client through POST /admin/clients and
// returns (client_id, client_secret). body fields are the wire names.
func topoCreateClient(t *testing.T, h *e2e.TestHarness, body map[string]any) (string, string) {
	t.Helper()
	if _, ok := body["redirect_uris"]; !ok {
		body["redirect_uris"] = []string{topoRedirect}
	}
	resp := h.AdminRequest(http.MethodPost, "/admin/clients", body)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /admin/clients %v: status %d body %s", body["client_name"], resp.StatusCode, raw)
	}
	var out struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.ClientID == "" {
		t.Fatalf("POST /admin/clients: no client_id in %s", raw)
	}
	return out.ClientID, out.ClientSecret
}

// topoDCR registers a client anonymously through POST /oauth/register — the
// door open to anyone on the internet under the default dcr.mode=open.
func topoDCR(t *testing.T, h *e2e.TestHarness, body map[string]any) (string, string) {
	t.Helper()
	if _, ok := body["redirect_uris"]; !ok {
		body["redirect_uris"] = []string{topoRedirect}
	}
	data, _ := json.Marshal(body)
	resp, err := http.Post(h.Issuer+"/oauth/register", "application/json", strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("POST /oauth/register: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /oauth/register: status %d body %s", resp.StatusCode, raw)
	}
	var out struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	_ = json.Unmarshal(raw, &out)
	return out.ClientID, out.ClientSecret
}

// topoAuditRow is one row of GET /admin/audit.
type topoAuditRow struct {
	Action   string `json:"action"`
	ActorID  string `json:"actor_id"`
	ClientID string `json:"client_id"`
	Detail   string `json:"detail"`
}

// topoAudit lists the most recent rows for action.
func topoAudit(t *testing.T, h *e2e.TestHarness, action string) []topoAuditRow {
	t.Helper()
	resp := h.AdminRequest(http.MethodGet, "/admin/audit?limit=500&action="+url.QueryEscape(action), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/audit?action=%s: status %d", action, resp.StatusCode)
	}
	var rows []topoAuditRow
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		t.Fatalf("decode audit rows: %v", err)
	}
	return rows
}

// topoExpectAudit fails the test unless some row for action satisfies match.
func topoExpectAudit(t *testing.T, h *e2e.TestHarness, action, what string, match func(topoAuditRow) bool) {
	t.Helper()
	rows := topoAudit(t, h, action)
	for _, r := range rows {
		if match(r) {
			return
		}
	}
	t.Errorf("audit: no %s row %s (have %d rows for the action)", action, what, len(rows))
}

// topoDetailHas reports whether detail carries every key=value needle.
func topoDetailHas(detail string, needles ...string) bool {
	for _, n := range needles {
		if !strings.Contains(detail, n) {
			return false
		}
	}
	return true
}

// topoScopes returns the sorted fields of a space-separated scope string.
func topoScopes(s string) []string {
	f := strings.Fields(s)
	sort.Strings(f)
	return f
}

// topoAssertScopeWithin fails when got names a scope outside allowed, or is
// empty when nonEmpty is set (a silently scope-less grant).
func topoAssertScopeWithin(t *testing.T, label, got string, nonEmpty bool, allowed ...string) {
	t.Helper()
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	for _, s := range strings.Fields(got) {
		if !ok[s] {
			t.Errorf("%s: scope %q is outside the entitled set %v (full scope %q)", label, s, allowed, got)
		}
	}
	if nonEmpty && strings.TrimSpace(got) == "" {
		t.Errorf("%s: issued scope is silently empty; want a documented default within %v or a refusal", label, allowed)
	}
}

// topoAud returns the aud claim as a slice.
func topoAud(claims map[string]any) []string {
	switch v := claims["aud"].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// topoActSub returns act.sub at the given depth (1 = act.sub, 2 = act.act.sub).
func topoActSub(claims map[string]any, depth int) string {
	cur := claims
	for i := 0; i < depth; i++ {
		next, _ := cur["act"].(map[string]any)
		if next == nil {
			return ""
		}
		cur = next
	}
	s, _ := cur["sub"].(string)
	return s
}

// topoConsentGrantID finds the consent grant for (user, client, resource slug).
func topoConsentGrantID(t *testing.T, h *e2e.TestHarness, userID, clientID, slug string) string {
	t.Helper()
	res := h.AdminGetResourceBySlug(slug)
	g := findActorConsentGrant(t, h, userID, clientID, res.ID)
	if g == nil {
		t.Fatalf("precondition: no consent grant for (%s, %s, %s)", userID, clientID, slug)
	}
	return g.ID
}

// topoRevokeConsent revokes a consent grant through the admin API.
func topoRevokeConsent(t *testing.T, h *e2e.TestHarness, grantID string) {
	t.Helper()
	resp := h.AdminRequest(http.MethodDelete, "/admin/grants/consent/"+grantID, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /admin/grants/consent/%s: status %d", grantID, resp.StatusCode)
	}
}

// topoAdminPatch issues an admin PATCH with no body and asserts 2xx.
func topoAdminPatch(t *testing.T, h *e2e.TestHarness, path string) {
	t.Helper()
	resp := h.AdminRequest(http.MethodPatch, path, nil)
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("PATCH %s: status %d body %s", path, resp.StatusCode, raw)
	}
}

// topoRSCreds registers introspection credentials bound to the resource with
// the given slug (policy.runtime.client_ids) — how a resource server is
// entitled to ask the AS about tokens audienced to it.
func topoRSCreds(t *testing.T, h *e2e.TestHarness, slug string) (string, string) {
	t.Helper()
	id, secret := topoCreateClient(t, h, map[string]any{
		"client_name":                slug + " resource server",
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "client_secret_post",
	})
	h.AdminAddRuntimeClientID(slug, id)
	return id, secret
}

// topoCode logs email in and returns a fresh code + verifier for (client,
// resource, scopes), consenting when the AS asks and reusing a remembered
// consent when it does not.
func topoCode(t *testing.T, h *e2e.TestHarness, email, clientID, resource string, scopes []string) (string, string) {
	t.Helper()
	c := topoLoggedIn(t, h, email)
	v, ch := topoPKCE()
	code := topoCodeFor(t, h, c, topoAuthorizeParams(clientID, topoRedirect, resource, strings.Join(scopes, " "), ch, "S256"), scopes)
	return code, v
}
