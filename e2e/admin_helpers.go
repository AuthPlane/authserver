//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// admin_helpers.go layers per-endpoint convenience methods on top of
// AdminRequest so e2e tests can drive the public admin HTTP API without
// reaching for the internal store accessors that retires.
//
// Design rules:
//   - Plain net/http only; no admin-API SDK (per  decision —
//     no admin SDK, harness uses net/http).
//   - Response shapes are decoded into local minimal structs. The
//     harness deliberately does NOT import internal/admin/dto so a
//     future taxonomic change in the wire format that the tests don't
//     observe can't break the lint or the suite.
//   - On any non-success status the helper t.Fatals with the response
//     body — admin operations in tests are setup, not behaviour-under-
//     test, so silent recovery would mask a deeper config bug.
//
// Callers wanting Admin* helpers must construct the harness with
// HarnessConfig{EnableAdminAPI: true}. AdminRequest already enforces
// this; the helpers below inherit the same precondition.

// AdminScope is a minimal subset of internal/admin/dto.ScopeView. The
// harness encodes scopes for resource creation; tests only ever read
// back fields they themselves wrote.
type AdminScope struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Upstream    string `json:"upstream,omitempty"`
}

// AdminResource is the harness-side view of a unified Resource. Field
// set is intentionally narrower than the wire response — additional
// JSON keys are ignored at decode time.
type AdminResource struct {
	ID               string       `json:"id"`
	Slug             string       `json:"slug"`
	URI              string       `json:"uri"`
	BackendKind      string       `json:"backend_kind"`
	BrokerProviderID string       `json:"broker_provider_id"`
	DisplayName      string       `json:"display_name"`
	Scopes           []AdminScope `json:"scopes"`
	Policy           AdminPolicy  `json:"policy"`
}

// AdminPolicy mirrors the admin-API PolicyView shape: Connect is a
// pointer so absence on Mint resources decodes to nil rather than zero.
type AdminPolicy struct {
	Exchange AdminExchangePolicy `json:"exchange"`
	Runtime  AdminRuntimePolicy  `json:"runtime"`
	Connect  *AdminConnectPolicy `json:"connect,omitempty"`
}

type AdminExchangePolicy struct {
	AllowedClientIDs []string `json:"allowed_client_ids"`
}

// AdminRuntimePolicy mirrors RuntimePolicyView. Empty client_ids
// means default-deny — no client may act as the Resource at runtime.
type AdminRuntimePolicy struct {
	ClientIDs []string `json:"client_ids"`
}

type AdminConnectPolicy struct {
	AllowedReturnURLs []string `json:"allowed_return_urls"`
}

// AdminBrokerProvider is the harness-side view of a BrokerProvider.
type AdminBrokerProvider struct {
	ID          string          `json:"id"`
	Slug        string          `json:"slug"`
	DisplayName string          `json:"display_name"`
	Protocol    string          `json:"protocol"`
	ConfigData  json.RawMessage `json:"config_data"`
}

// CreateResourceSpec is the harness-side input for AdminCreateResource.
// Mirrors the wire request body of POST /admin/resources but uses the
// minimal AdminScope/AdminPolicy types.
type CreateResourceSpec struct {
	Slug               string
	URI                string
	BackendKind        string // "mint" or "broker"
	BrokerProviderID   string
	BrokerProviderSlug string // — preferred over UUID
	DisplayName        string
	Scopes             []AdminScope
	Policy             *AdminPolicy
}

// CreateBrokerProviderSpec is the harness-side input for
// AdminCreateBrokerProvider. ConfigData accepts either []byte or a
// JSON-marshalable value; the helper round-trips it as RawMessage.
type CreateBrokerProviderSpec struct {
	Slug        string
	DisplayName string
	Protocol    string // typically "oauth"
	ConfigData  any    // []byte | map[string]any | struct
}

// AdminCreateResource registers a new Resource via POST /admin/resources
// and returns its server-generated ID. Fails the test on any non-201
// response.
func (h *TestHarness) AdminCreateResource(spec CreateResourceSpec) string {
	h.T.Helper()

	body := map[string]any{
		"slug":         spec.Slug,
		"backend_kind": spec.BackendKind,
		"display_name": spec.DisplayName,
	}
	if spec.URI != "" {
		body["uri"] = spec.URI
	}
	if spec.BrokerProviderID != "" {
		body["broker_provider_id"] = spec.BrokerProviderID
	}
	if spec.BrokerProviderSlug != "" {
		body["broker_provider_slug"] = spec.BrokerProviderSlug
	}
	if spec.Scopes != nil {
		body["scopes"] = spec.Scopes
	}
	if spec.Policy != nil {
		body["policy"] = spec.Policy
	}

	resp := h.AdminRequest("POST", "/admin/resources", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		h.T.Fatalf("AdminCreateResource: status %d, body %s", resp.StatusCode, string(raw))
	}

	var out AdminResource
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.T.Fatalf("AdminCreateResource: decode response: %v", err)
	}
	if out.ID == "" {
		h.T.Fatalf("AdminCreateResource: missing id in response")
	}
	return out.ID
}

// AdminGetResourceBySlug looks up a single Resource via the
// slug-lookup mode (GET /admin/resources?slug=...). Fails the test on
// any non-200 (404 included — callers expecting "miss" must use the
// AdminTryGetResourceBySlug variant if/when one is added).
func (h *TestHarness) AdminGetResourceBySlug(slug string) AdminResource {
	h.T.Helper()
	resp := h.AdminRequest("GET", "/admin/resources?slug="+url.QueryEscape(slug), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		h.T.Fatalf("AdminGetResourceBySlug(%q): status %d, body %s", slug, resp.StatusCode, string(raw))
	}
	var out AdminResource
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.T.Fatalf("AdminGetResourceBySlug(%q): decode response: %v", slug, err)
	}
	return out
}

// AdminCreateBrokerProvider registers a new BrokerProvider and returns
// its server-generated ID.
func (h *TestHarness) AdminCreateBrokerProvider(spec CreateBrokerProviderSpec) string {
	h.T.Helper()

	var configData json.RawMessage
	switch v := spec.ConfigData.(type) {
	case nil:
		configData = json.RawMessage("{}")
	case []byte:
		configData = json.RawMessage(v)
	case json.RawMessage:
		configData = v
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			h.T.Fatalf("AdminCreateBrokerProvider: marshal config_data: %v", err)
		}
		configData = raw
	}

	body := map[string]any{
		"slug":         spec.Slug,
		"display_name": spec.DisplayName,
		"protocol":     spec.Protocol,
		"config_data":  configData,
	}

	resp := h.AdminRequest("POST", "/admin/broker-providers", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		h.T.Fatalf("AdminCreateBrokerProvider: status %d, body %s", resp.StatusCode, string(raw))
	}

	var out AdminBrokerProvider
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.T.Fatalf("AdminCreateBrokerProvider: decode response: %v", err)
	}
	if out.ID == "" {
		h.T.Fatalf("AdminCreateBrokerProvider: missing id in response")
	}
	return out.ID
}

// AdminGetBrokerProviderBySlug looks up a single BrokerProvider via the
// slug-lookup mode (GET /admin/broker-providers?slug=...).
func (h *TestHarness) AdminGetBrokerProviderBySlug(slug string) AdminBrokerProvider {
	h.T.Helper()
	resp := h.AdminRequest("GET", "/admin/broker-providers?slug="+url.QueryEscape(slug), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		h.T.Fatalf("AdminGetBrokerProviderBySlug(%q): status %d, body %s", slug, resp.StatusCode, string(raw))
	}
	var out AdminBrokerProvider
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.T.Fatalf("AdminGetBrokerProviderBySlug(%q): decode response: %v", slug, err)
	}
	return out
}

// --- policy.exchange.allowed_client_ids ---

// AdminAddAllowedClient adds clientID to the resource's
// policy.exchange.allowed_client_ids and returns the updated list.
func (h *TestHarness) AdminAddAllowedClient(slug, clientID string) []string {
	h.T.Helper()
	body := map[string]any{"client_id": clientID}
	path := fmt.Sprintf("/admin/resources/%s/policy/exchange/allowed-clients", url.PathEscape(slug))
	resp := h.AdminRequest("POST", path, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		h.T.Fatalf("AdminAddAllowedClient(%q,%q): status %d, body %s", slug, clientID, resp.StatusCode, string(raw))
	}
	var out struct {
		AllowedClientIDs []string `json:"allowed_client_ids"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.T.Fatalf("AdminAddAllowedClient: decode response: %v", err)
	}
	return out.AllowedClientIDs
}

// AdminRemoveAllowedClient removes clientID from the resource's
// policy.exchange.allowed_client_ids and returns the updated list.
func (h *TestHarness) AdminRemoveAllowedClient(slug, clientID string) []string {
	h.T.Helper()
	path := fmt.Sprintf("/admin/resources/%s/policy/exchange/allowed-clients/%s",
		url.PathEscape(slug), url.PathEscape(clientID))
	resp := h.AdminRequest("DELETE", path, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		h.T.Fatalf("AdminRemoveAllowedClient(%q,%q): status %d, body %s", slug, clientID, resp.StatusCode, string(raw))
	}
	var out struct {
		AllowedClientIDs []string `json:"allowed_client_ids"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.T.Fatalf("AdminRemoveAllowedClient: decode response: %v", err)
	}
	return out.AllowedClientIDs
}

// AdminListAllowedClients reads the resource's
// policy.exchange.allowed_client_ids.
func (h *TestHarness) AdminListAllowedClients(slug string) []string {
	h.T.Helper()
	path := fmt.Sprintf("/admin/resources/%s/policy/exchange/allowed-clients", url.PathEscape(slug))
	resp := h.AdminRequest("GET", path, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		h.T.Fatalf("AdminListAllowedClients(%q): status %d, body %s", slug, resp.StatusCode, string(raw))
	}
	var out struct {
		AllowedClientIDs []string `json:"allowed_client_ids"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.T.Fatalf("AdminListAllowedClients: decode response: %v", err)
	}
	return out.AllowedClientIDs
}

// AdminCreatePublicClient registers a public client (token_endpoint_auth_method=none)
// via POST /admin/clients with an auto-generated client_id and returns it.
// Used by e2e to exercise the runtime.client_ids gate without the
// retired slug==client_id convention. redirectURIs may be nil — defaults to
// the standard loopback used by the harness PKCE flows.
func (h *TestHarness) AdminCreatePublicClient(name string, grantTypes []string, scope string, redirectURIs []string) string {
	h.T.Helper()
	if len(redirectURIs) == 0 {
		redirectURIs = []string{"http://localhost:9999/callback"}
	}
	body := map[string]any{
		"client_name":                name,
		"redirect_uris":              redirectURIs,
		"grant_types":                grantTypes,
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"scope":                      scope,
	}
	resp := h.AdminRequest("POST", "/admin/clients", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		h.T.Fatalf("AdminCreatePublicClient(%q): status %d, body %s", name, resp.StatusCode, string(raw))
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.T.Fatalf("AdminCreatePublicClient: decode response: %v", err)
	}
	if out.ClientID == "" {
		h.T.Fatalf("AdminCreatePublicClient: missing client_id in response")
	}
	return out.ClientID
}

// AdminCreateConfidentialClient registers a confidential client (non-agent)
// via POST /admin/clients with an auto-generated client_id and returns
// (client_id, client_secret). Use AdminCreateAgentClient when the test
// needs the IsAgent flag flipped for agent-identity wiring.
func (h *TestHarness) AdminCreateConfidentialClient(name string, grantTypes []string, scope string) (string, string) {
	h.T.Helper()
	body := map[string]any{
		"client_name":                name,
		"redirect_uris":              []string{"http://localhost:9999/callback"},
		"grant_types":                grantTypes,
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "client_secret_post",
		"scope":                      scope,
	}
	resp := h.AdminRequest("POST", "/admin/clients", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		h.T.Fatalf("AdminCreateConfidentialClient(%q): status %d, body %s", name, resp.StatusCode, string(raw))
	}
	var out struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.T.Fatalf("AdminCreateConfidentialClient: decode response: %v", err)
	}
	if out.ClientID == "" || out.ClientSecret == "" {
		h.T.Fatalf("AdminCreateConfidentialClient: missing client_id or client_secret in response")
	}
	return out.ClientID, out.ClientSecret
}

// AdminCreateAgentClient registers a confidential agent client via
// POST /admin/clients with an auto-generated client_id and returns
// (client_id, client_secret). caller-chosen IDs are no longer
// possible from tests; the AS auto-generates the client_id and tests
// bind it to a Resource via policy.runtime.client_ids.
func (h *TestHarness) AdminCreateAgentClient(name string, grantTypes []string, scope, description string) (string, string) {
	h.T.Helper()
	body := map[string]any{
		"client_name":                name,
		"redirect_uris":              []string{"http://localhost:9999/callback"},
		"grant_types":                grantTypes,
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "client_secret_post",
		"scope":                      scope,
		"agent":                      true,
		"agent_description":          description,
	}
	resp := h.AdminRequest("POST", "/admin/clients", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		h.T.Fatalf("AdminCreateAgentClient(%q): status %d, body %s", name, resp.StatusCode, string(raw))
	}
	var out struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.T.Fatalf("AdminCreateAgentClient: decode response: %v", err)
	}
	if out.ClientID == "" || out.ClientSecret == "" {
		h.T.Fatalf("AdminCreateAgentClient: missing client_id or client_secret in response")
	}
	return out.ClientID, out.ClientSecret
}

// --- policy.runtime.client_ids ---

// AdminAddRuntimeClientID adds clientID to the resource's
// policy.runtime.client_ids and returns the updated list.
func (h *TestHarness) AdminAddRuntimeClientID(slug, clientID string) []string {
	h.T.Helper()
	body := map[string]any{"client_id": clientID}
	path := fmt.Sprintf("/admin/resources/%s/policy/runtime/client-ids", url.PathEscape(slug))
	resp := h.AdminRequest("POST", path, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		h.T.Fatalf("AdminAddRuntimeClientID(%q,%q): status %d, body %s", slug, clientID, resp.StatusCode, string(raw))
	}
	var out struct {
		ClientIDs []string `json:"client_ids"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.T.Fatalf("AdminAddRuntimeClientID: decode response: %v", err)
	}
	return out.ClientIDs
}

// AdminRemoveRuntimeClientID removes clientID from the resource's
// policy.runtime.client_ids and returns the updated list.
func (h *TestHarness) AdminRemoveRuntimeClientID(slug, clientID string) []string {
	h.T.Helper()
	path := fmt.Sprintf("/admin/resources/%s/policy/runtime/client-ids/%s",
		url.PathEscape(slug), url.PathEscape(clientID))
	resp := h.AdminRequest("DELETE", path, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		h.T.Fatalf("AdminRemoveRuntimeClientID(%q,%q): status %d, body %s", slug, clientID, resp.StatusCode, string(raw))
	}
	var out struct {
		ClientIDs []string `json:"client_ids"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.T.Fatalf("AdminRemoveRuntimeClientID: decode response: %v", err)
	}
	return out.ClientIDs
}

// AdminListRuntimeClientIDs reads the resource's policy.runtime.client_ids.
func (h *TestHarness) AdminListRuntimeClientIDs(slug string) []string {
	h.T.Helper()
	path := fmt.Sprintf("/admin/resources/%s/policy/runtime/client-ids", url.PathEscape(slug))
	resp := h.AdminRequest("GET", path, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		h.T.Fatalf("AdminListRuntimeClientIDs(%q): status %d, body %s", slug, resp.StatusCode, string(raw))
	}
	var out struct {
		ClientIDs []string `json:"client_ids"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.T.Fatalf("AdminListRuntimeClientIDs: decode response: %v", err)
	}
	return out.ClientIDs
}

// --- policy.connect.allowed_return_urls ---

// AdminAddAllowedReturnURL adds returnURL to the resource's
// policy.connect.allowed_return_urls and returns the updated list.
func (h *TestHarness) AdminAddAllowedReturnURL(slug, returnURL string) []string {
	h.T.Helper()
	body := map[string]any{"url": returnURL}
	path := fmt.Sprintf("/admin/resources/%s/policy/connect/allowed-return-urls", url.PathEscape(slug))
	resp := h.AdminRequest("POST", path, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		h.T.Fatalf("AdminAddAllowedReturnURL(%q,%q): status %d, body %s", slug, returnURL, resp.StatusCode, string(raw))
	}
	var out struct {
		AllowedReturnURLs []string `json:"allowed_return_urls"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.T.Fatalf("AdminAddAllowedReturnURL: decode response: %v", err)
	}
	return out.AllowedReturnURLs
}

// AdminRemoveAllowedReturnURL removes returnURL from the resource's
// policy.connect.allowed_return_urls and returns the updated list.
// The URL is passed via the `url` query parameter.
func (h *TestHarness) AdminRemoveAllowedReturnURL(slug, returnURL string) []string {
	h.T.Helper()
	path := fmt.Sprintf("/admin/resources/%s/policy/connect/allowed-return-urls?url=%s",
		url.PathEscape(slug), url.QueryEscape(returnURL))
	resp := h.AdminRequest("DELETE", path, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		h.T.Fatalf("AdminRemoveAllowedReturnURL(%q,%q): status %d, body %s", slug, returnURL, resp.StatusCode, string(raw))
	}
	var out struct {
		AllowedReturnURLs []string `json:"allowed_return_urls"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.T.Fatalf("AdminRemoveAllowedReturnURL: decode response: %v", err)
	}
	return out.AllowedReturnURLs
}

// AdminListAllowedReturnURLs reads the resource's
// policy.connect.allowed_return_urls. Fails the test on Mint resources
// (the AS returns 400 — Connect policy is broker-only).
func (h *TestHarness) AdminListAllowedReturnURLs(slug string) []string {
	h.T.Helper()
	path := fmt.Sprintf("/admin/resources/%s/policy/connect/allowed-return-urls", url.PathEscape(slug))
	resp := h.AdminRequest("GET", path, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		h.T.Fatalf("AdminListAllowedReturnURLs(%q): status %d, body %s", slug, resp.StatusCode, string(raw))
	}
	var out struct {
		AllowedReturnURLs []string `json:"allowed_return_urls"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.T.Fatalf("AdminListAllowedReturnURLs: decode response: %v", err)
	}
	return out.AllowedReturnURLs
}

// --- Fronting links ---

// CreateFrontingLinkSpec describes a fronting link for the e2e admin
// helper. ScopeMap is the wire JSON shape: {"src1": ["dst1","dst2"], ...}.
type CreateFrontingLinkSpec struct {
	Source   string
	Target   string
	ScopeMap map[string][]string
}

// AdminCreateFrontingLink POSTs /admin/fronting and fails the test on
// non-2xx response. Body field names match the admin handler's
// createFrontingLinkRequest shape (source/target/scope_map — NOT
// source_slug/target_slug).
func (h *TestHarness) AdminCreateFrontingLink(spec CreateFrontingLinkSpec) {
	h.T.Helper()
	body := map[string]any{
		"source":    spec.Source,
		"target":    spec.Target,
		"scope_map": spec.ScopeMap,
	}
	resp := h.AdminRequest("POST", "/admin/fronting", body)
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(resp.Body)
		h.T.Fatalf("AdminCreateFrontingLink %s->%s: status %d body=%s",
			spec.Source, spec.Target, resp.StatusCode, string(raw))
	}
}

// AdminDeleteFrontingLink DELETEs /admin/fronting/{source}/{target}.
// Fails the test on non-2xx and non-404 (404 is treated as a no-op so
// the helper is idempotent for cleanup paths).
func (h *TestHarness) AdminDeleteFrontingLink(source, target string) {
	h.T.Helper()
	path := "/admin/fronting/" + url.PathEscape(source) + "/" + url.PathEscape(target)
	resp := h.AdminRequest("DELETE", path, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK &&
		resp.StatusCode != http.StatusNoContent &&
		resp.StatusCode != http.StatusNotFound {
		raw, _ := io.ReadAll(resp.Body)
		h.T.Fatalf("AdminDeleteFrontingLink %s->%s: status %d body=%s",
			source, target, resp.StatusCode, string(raw))
	}
}
