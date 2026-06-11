//go:build integration

package admin_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
)

// These tests cover the per-policy-field admin endpoints added under
// +. They satisfy Gate 0 by construction: every fixture
// (clients, broker providers, resources) is set up via the public admin
// API surface — no env.stores.Stores.* writes, no internal/services
// imports, no internal store reads. The pattern is the model for every
// new test added during .

// adminCreateClient registers a confidential client via POST /admin/clients
// and returns its client_id. Use this in place of seed* helpers for any
// test that needs a client to reference from a resource policy.
func adminCreateClient(t *testing.T, env *adminTestEnv, name string) string {
	t.Helper()
	body := map[string]any{
		"client_name":                name,
		"redirect_uris":              []string{"https://app.example.com/cb"},
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      "openid",
	}
	resp := env.doRequest(t, "POST", "/admin/clients", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create client %q: %d %s", name, resp.StatusCode, string(b))
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode create client: %v", err)
	}
	id, _ := out["client_id"].(string)
	if id == "" {
		t.Fatal("expected client_id in create response")
	}
	return id
}

// adminCreateBrokerResource registers a broker provider + a Broker resource
// referencing it via the public admin API and returns the resource slug.
func adminCreateBrokerResource(t *testing.T, env *adminTestEnv, slug string) string {
	t.Helper()

	bpResp := env.doRequest(t, "POST", "/admin/broker-providers", map[string]any{
		"slug":         slug + "-provider",
		"display_name": slug + " provider",
		"protocol":     "oauth",
		"config_data":  map[string]any{},
	})
	defer bpResp.Body.Close()
	if bpResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(bpResp.Body)
		t.Fatalf("seed broker provider: %d %s", bpResp.StatusCode, string(b))
	}
	var bp map[string]any
	json.NewDecoder(bpResp.Body).Decode(&bp)
	bpID, _ := bp["id"].(string)

	resp := env.doRequest(t, "POST", "/admin/resources", map[string]any{
		"slug":               slug,
		"uri":                "https://" + slug + ".example/api",
		"backend_kind":       "broker",
		"broker_provider_id": bpID,
		"display_name":       slug,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create broker resource: %d %s", resp.StatusCode, string(b))
	}
	return slug
}

// adminCreateMintResource registers a Mint resource via the public admin
// API and returns its slug.
func adminCreateMintResource(t *testing.T, env *adminTestEnv, slug string) string {
	t.Helper()
	resp := env.doRequest(t, "POST", "/admin/resources", map[string]any{
		"slug":         slug,
		"backend_kind": "mint",
		"display_name": slug,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create mint resource: %d %s", resp.StatusCode, string(b))
	}
	return slug
}

// decodeClientList decodes the body of a /policy/exchange/allowed-clients
// response to its allowed_client_ids slice.
func decodeClientList(t *testing.T, resp *http.Response) []string {
	t.Helper()
	var out struct {
		AllowedClientIDs []string `json:"allowed_client_ids"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return out.AllowedClientIDs
}

func decodeReturnURLList(t *testing.T, resp *http.Response) []string {
	t.Helper()
	var out struct {
		AllowedReturnURLs []string `json:"allowed_return_urls"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return out.AllowedReturnURLs
}

// --- exchange.allowed_client_ids ---

func TestAdmin_ResourcePolicy_AllowedClients_AddListRemove(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)
	slug := adminCreateMintResource(t, env, "mint-policy-clients")
	clientID := adminCreateClient(t, env, "Agent A")

	// Initial list is empty.
	listResp := env.doRequest(t, "GET", "/admin/resources/"+slug+"/policy/exchange/allowed-clients", nil)
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list initial: status %d", listResp.StatusCode)
	}
	if got := decodeClientList(t, listResp); len(got) != 0 {
		t.Errorf("initial list: got %v, want []", got)
	}

	// Add returns the updated list.
	addResp := env.doRequest(t, "POST", "/admin/resources/"+slug+"/policy/exchange/allowed-clients", map[string]any{
		"client_id": clientID,
	})
	defer addResp.Body.Close()
	if addResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(addResp.Body)
		t.Fatalf("add: status %d, body %s", addResp.StatusCode, string(b))
	}
	got := decodeClientList(t, addResp)
	if len(got) != 1 || got[0] != clientID {
		t.Errorf("post-add list: got %v, want [%s]", got, clientID)
	}

	// Idempotent re-add.
	addAgainResp := env.doRequest(t, "POST", "/admin/resources/"+slug+"/policy/exchange/allowed-clients", map[string]any{
		"client_id": clientID,
	})
	defer addAgainResp.Body.Close()
	if addAgainResp.StatusCode != http.StatusOK {
		t.Fatalf("idempotent add: status %d", addAgainResp.StatusCode)
	}
	if got := decodeClientList(t, addAgainResp); len(got) != 1 {
		t.Errorf("idempotent add list: got %v, want 1 entry", got)
	}

	// GET reflects the add.
	listAfterResp := env.doRequest(t, "GET", "/admin/resources/"+slug+"/policy/exchange/allowed-clients", nil)
	defer listAfterResp.Body.Close()
	if got := decodeClientList(t, listAfterResp); len(got) != 1 || got[0] != clientID {
		t.Errorf("list after add: got %v, want [%s]", got, clientID)
	}

	// Remove returns the updated list (empty).
	delResp := env.doRequest(t, "DELETE", "/admin/resources/"+slug+"/policy/exchange/allowed-clients/"+clientID, nil)
	defer delResp.Body.Close()
	if delResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(delResp.Body)
		t.Fatalf("remove: status %d, body %s", delResp.StatusCode, string(b))
	}
	if got := decodeClientList(t, delResp); len(got) != 0 {
		t.Errorf("post-remove list: got %v, want []", got)
	}

	// Idempotent re-remove.
	delAgainResp := env.doRequest(t, "DELETE", "/admin/resources/"+slug+"/policy/exchange/allowed-clients/"+clientID, nil)
	defer delAgainResp.Body.Close()
	if delAgainResp.StatusCode != http.StatusOK {
		t.Fatalf("idempotent remove: status %d", delAgainResp.StatusCode)
	}
}

func TestAdmin_ResourcePolicy_AllowedClients_AddRejectsUnknownClient(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)
	slug := adminCreateMintResource(t, env, "mint-unknown-client")

	resp := env.doRequest(t, "POST", "/admin/resources/"+slug+"/policy/exchange/allowed-clients", map[string]any{
		"client_id": "client-that-does-not-exist",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("add unknown client: status %d, want 400, body %s", resp.StatusCode, string(b))
	}
}

func TestAdmin_ResourcePolicy_AllowedClients_AddRejectsEmptyClient(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)
	slug := adminCreateMintResource(t, env, "mint-empty-client")

	resp := env.doRequest(t, "POST", "/admin/resources/"+slug+"/policy/exchange/allowed-clients", map[string]any{
		"client_id": "",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("add empty client: status %d, want 400", resp.StatusCode)
	}
}

func TestAdmin_ResourcePolicy_AllowedClients_UnknownSlug(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)
	clientID := adminCreateClient(t, env, "OrphanClient")

	resp := env.doRequest(t, "POST", "/admin/resources/no-such-slug/policy/exchange/allowed-clients", map[string]any{
		"client_id": clientID,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("add to unknown slug: status %d, want 404", resp.StatusCode)
	}
}

func TestAdmin_ResourcePolicy_AllowedClients_AuthRequired(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)
	slug := adminCreateMintResource(t, env, "mint-noauth")

	resp, err := http.Get(env.ts.URL + "/admin/resources/" + slug + "/policy/exchange/allowed-clients")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", resp.StatusCode)
	}
}

// --- connect.allowed_return_urls ---

func TestAdmin_ResourcePolicy_AllowedReturnURLs_AddListRemove(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)
	slug := adminCreateBrokerResource(t, env, "broker-policy-urls")

	const target = "https://app.example.com/connected"

	listResp := env.doRequest(t, "GET", "/admin/resources/"+slug+"/policy/connect/allowed-return-urls", nil)
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list initial: status %d", listResp.StatusCode)
	}
	if got := decodeReturnURLList(t, listResp); len(got) != 0 {
		t.Errorf("initial list: got %v, want []", got)
	}

	addResp := env.doRequest(t, "POST", "/admin/resources/"+slug+"/policy/connect/allowed-return-urls", map[string]any{
		"url": target,
	})
	defer addResp.Body.Close()
	if addResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(addResp.Body)
		t.Fatalf("add: status %d, body %s", addResp.StatusCode, string(b))
	}
	if got := decodeReturnURLList(t, addResp); len(got) != 1 || got[0] != target {
		t.Errorf("post-add list: got %v, want [%s]", got, target)
	}

	// Idempotent re-add.
	addAgainResp := env.doRequest(t, "POST", "/admin/resources/"+slug+"/policy/connect/allowed-return-urls", map[string]any{
		"url": target,
	})
	defer addAgainResp.Body.Close()
	if addAgainResp.StatusCode != http.StatusOK {
		t.Fatalf("idempotent add: status %d", addAgainResp.StatusCode)
	}

	// Remove via query string (URL with `:` and `/`).
	delPath := "/admin/resources/" + slug + "/policy/connect/allowed-return-urls?url=" + url.QueryEscape(target)
	delResp := env.doRequest(t, "DELETE", delPath, nil)
	defer delResp.Body.Close()
	if delResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(delResp.Body)
		t.Fatalf("remove: status %d, body %s", delResp.StatusCode, string(b))
	}
	if got := decodeReturnURLList(t, delResp); len(got) != 0 {
		t.Errorf("post-remove list: got %v, want []", got)
	}

	// Idempotent re-remove.
	delAgainResp := env.doRequest(t, "DELETE", delPath, nil)
	defer delAgainResp.Body.Close()
	if delAgainResp.StatusCode != http.StatusOK {
		t.Fatalf("idempotent remove: status %d", delAgainResp.StatusCode)
	}
}

func TestAdmin_ResourcePolicy_AllowedReturnURLs_AcceptsLoopbackWildcard(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)
	slug := adminCreateBrokerResource(t, env, "broker-loopback")

	const target = "http://localhost:*"
	addResp := env.doRequest(t, "POST", "/admin/resources/"+slug+"/policy/connect/allowed-return-urls", map[string]any{
		"url": target,
	})
	defer addResp.Body.Close()
	if addResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(addResp.Body)
		t.Fatalf("add loopback wildcard: status %d, body %s", addResp.StatusCode, string(b))
	}
	if got := decodeReturnURLList(t, addResp); len(got) != 1 || got[0] != target {
		t.Errorf("post-add list: got %v, want [%s]", got, target)
	}
}

func TestAdmin_ResourcePolicy_AllowedReturnURLs_RejectsMalformed(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)
	slug := adminCreateBrokerResource(t, env, "broker-malformed")

	cases := []struct {
		name, value string
	}{
		{"empty", ""},
		{"relative", "/just/a/path"},
		{"non-http-scheme", "ftp://example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := env.doRequest(t, "POST", "/admin/resources/"+slug+"/policy/connect/allowed-return-urls", map[string]any{
				"url": tc.value,
			})
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				b, _ := io.ReadAll(resp.Body)
				t.Fatalf("status %d, want 400; body %s", resp.StatusCode, string(b))
			}
		})
	}
}

func TestAdmin_ResourcePolicy_AllowedReturnURLs_MintResourceRejected(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)
	slug := adminCreateMintResource(t, env, "mint-no-connect")

	addResp := env.doRequest(t, "POST", "/admin/resources/"+slug+"/policy/connect/allowed-return-urls", map[string]any{
		"url": "https://app.example.com/connected",
	})
	defer addResp.Body.Close()
	if addResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("add to mint: status %d, want 400", addResp.StatusCode)
	}

	listResp := env.doRequest(t, "GET", "/admin/resources/"+slug+"/policy/connect/allowed-return-urls", nil)
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("list on mint: status %d, want 400", listResp.StatusCode)
	}
}

func TestAdmin_ResourcePolicy_AllowedReturnURLs_DeleteRejectsMissingQueryParam(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)
	slug := adminCreateBrokerResource(t, env, "broker-no-query")

	resp := env.doRequest(t, "DELETE", "/admin/resources/"+slug+"/policy/connect/allowed-return-urls", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("delete without ?url: status %d, want 400", resp.StatusCode)
	}
}

func TestAdmin_ResourcePolicy_AllowedReturnURLs_UnknownSlug(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)

	resp := env.doRequest(t, "POST", "/admin/resources/no-such-broker/policy/connect/allowed-return-urls", map[string]any{
		"url": "https://app.example.com/connected",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("add to unknown slug: status %d, want 404", resp.StatusCode)
	}
}

// --- runtime.client_ids ---

func decodeRuntimeClientIDs(t *testing.T, resp *http.Response) []string {
	t.Helper()
	var out struct {
		ClientIDs []string `json:"client_ids"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return out.ClientIDs
}

func TestAdmin_ResourcePolicy_RuntimeClientIDs_AddListRemove(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)
	slug := adminCreateMintResource(t, env, "mint-runtime")
	clientID := adminCreateClient(t, env, "Gateway")

	listResp := env.doRequest(t, "GET", "/admin/resources/"+slug+"/policy/runtime/client-ids", nil)
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list initial: status %d", listResp.StatusCode)
	}
	if got := decodeRuntimeClientIDs(t, listResp); len(got) != 0 {
		t.Errorf("initial list: got %v, want []", got)
	}

	addResp := env.doRequest(t, "POST", "/admin/resources/"+slug+"/policy/runtime/client-ids", map[string]any{
		"client_id": clientID,
	})
	defer addResp.Body.Close()
	if addResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(addResp.Body)
		t.Fatalf("add: status %d, body %s", addResp.StatusCode, string(b))
	}
	got := decodeRuntimeClientIDs(t, addResp)
	if len(got) != 1 || got[0] != clientID {
		t.Errorf("post-add list: got %v, want [%s]", got, clientID)
	}

	// Idempotent re-add.
	addAgainResp := env.doRequest(t, "POST", "/admin/resources/"+slug+"/policy/runtime/client-ids", map[string]any{
		"client_id": clientID,
	})
	defer addAgainResp.Body.Close()
	if addAgainResp.StatusCode != http.StatusOK {
		t.Fatalf("idempotent add: status %d", addAgainResp.StatusCode)
	}
	if got := decodeRuntimeClientIDs(t, addAgainResp); len(got) != 1 {
		t.Errorf("idempotent add list: got %v, want 1 entry", got)
	}

	listAfterResp := env.doRequest(t, "GET", "/admin/resources/"+slug+"/policy/runtime/client-ids", nil)
	defer listAfterResp.Body.Close()
	if got := decodeRuntimeClientIDs(t, listAfterResp); len(got) != 1 || got[0] != clientID {
		t.Errorf("list after add: got %v, want [%s]", got, clientID)
	}

	delResp := env.doRequest(t, "DELETE", "/admin/resources/"+slug+"/policy/runtime/client-ids/"+clientID, nil)
	defer delResp.Body.Close()
	if delResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(delResp.Body)
		t.Fatalf("remove: status %d, body %s", delResp.StatusCode, string(b))
	}
	if got := decodeRuntimeClientIDs(t, delResp); len(got) != 0 {
		t.Errorf("post-remove list: got %v, want []", got)
	}

	// Idempotent re-remove.
	delAgainResp := env.doRequest(t, "DELETE", "/admin/resources/"+slug+"/policy/runtime/client-ids/"+clientID, nil)
	defer delAgainResp.Body.Close()
	if delAgainResp.StatusCode != http.StatusOK {
		t.Fatalf("idempotent remove: status %d", delAgainResp.StatusCode)
	}
}

func TestAdmin_ResourcePolicy_RuntimeClientIDs_AddRejectsUnknownClient(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)
	slug := adminCreateMintResource(t, env, "mint-runtime-unknown")

	resp := env.doRequest(t, "POST", "/admin/resources/"+slug+"/policy/runtime/client-ids", map[string]any{
		"client_id": "client-that-does-not-exist",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("add unknown client: status %d, want 400, body %s", resp.StatusCode, string(b))
	}
}

func TestAdmin_ResourcePolicy_RuntimeClientIDs_UnknownSlug(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)
	clientID := adminCreateClient(t, env, "Orphan-RT")

	resp := env.doRequest(t, "POST", "/admin/resources/no-such-runtime/policy/runtime/client-ids", map[string]any{
		"client_id": clientID,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("add to unknown slug: status %d, want 404", resp.StatusCode)
	}
}
