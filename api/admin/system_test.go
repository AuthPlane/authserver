package admin_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	apiadmin "github.com/authplane/authserver/api/admin"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

const sysAPIKey = "test-admin-api-key-123"

// erroringDPoP is a DPoPConfigProvider that always fails, to exercise the
// 500 degradation path.
type erroringDPoP struct{}

func (erroringDPoP) Config(context.Context) (output.DPoPConfig, error) {
	return output.DPoPConfig{}, errors.New("boom")
}

func newSystemServer(t *testing.T, sys *apiadmin.SystemDeps) *httptest.Server {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := observability.NewNoop()
	adminSvc := services.NewAdminService(
		stores.Client, stores.User, stores.Token, stores.Audit,
		obs, nil,
		services.WithMachineTokenStore(stores.MachineToken),
		services.WithRevocationStore(stores.Revocation),
	)
	srv := mustNewServer(t, config.AdminConfig{
		Enabled: true, Address: ":0", APIKey: sysAPIKey,
	}, adminSvc, obs, apiadmin.OptionalDeps{System: sys})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func getConfig(t *testing.T, url string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url+"/admin/system/config", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+sysAPIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	if resp.StatusCode == http.StatusOK {
		_ = json.NewDecoder(resp.Body).Decode(&body)
	}
	return resp.StatusCode, body
}

func staticSystemDeps() *apiadmin.SystemDeps {
	return &apiadmin.SystemDeps{
		Version:           "v-test",
		StartTime:         time.Now(),
		StorageDriver:     "sqlite",
		KeyStoreDriver:    "db",
		EncryptionDriver:  "none",
		SigningAlgorithm:  "ES256",
		RateLimitEnabled:  true,
		Issuer:            static.NewIssuerProvider("https://as.example"),
		DPoP:              static.NewDPoPConfigProvider(output.DPoPConfig{Enabled: true, NonceTTL: 60 * time.Second, RequireNonce: true}),
		DCRMode:           static.NewDCRModeProvider("open", nil),
		TokenExchange:     static.NewTokenExchangeConfigProvider(output.TokenExchangeConfig{Enabled: true, MaxChainDepth: 3}),
		ClientCredentials: static.NewClientCredentialsConfigProvider(output.ClientCredentialsConfig{Enabled: false}),
		Agents:            static.NewAgentsConfigProvider(output.AgentsConfig{EnableJWKSListing: true, AgentIdentityEnabled: false}),
		OIDC:              static.NewOIDCConfigProvider(output.OIDCConfig{Enabled: true}),
		OAuth:             static.NewOAuthConfigProvider(output.OAuthConfig{DefaultClientScope: "tools/read"}),
	}
}

func TestSystemConfig_ReflectsProviders(t *testing.T) {
	ts := newSystemServer(t, staticSystemDeps())
	status, body := getConfig(t, ts.URL)
	if status != http.StatusOK {
		t.Fatalf("status: got %d, want 200", status)
	}
	if body["issuer"] != "https://as.example" {
		t.Fatalf("issuer: got %v", body["issuer"])
	}
	dpop := body["dpop"].(map[string]any)
	if dpop["enabled"] != true || dpop["nonce_ttl"] != "1m0s" {
		t.Fatalf("dpop: got %v", dpop)
	}
	if body["oidc"].(map[string]any)["enabled"] != true {
		t.Fatalf("oidc: got %v", body["oidc"])
	}
	if body["dcr"].(map[string]any)["mode"] != "open" {
		t.Fatalf("dcr: got %v", body["dcr"])
	}
	tx := body["token_exchange"].(map[string]any)
	if tx["enabled"] != true || tx["max_chain_depth"] != float64(3) {
		t.Fatalf("token_exchange: got %v", tx)
	}
	if body["client_credentials"].(map[string]any)["enabled"] != false {
		t.Fatalf("client_credentials: got %v", body["client_credentials"])
	}
	agents := body["agents"].(map[string]any)
	if agents["enabled"] != false || agents["jwks_listing"] != true {
		t.Fatalf("agents: got %v", agents)
	}
}

func TestSystemConfig_ProviderError500(t *testing.T) {
	deps := staticSystemDeps()
	deps.DPoP = erroringDPoP{}
	ts := newSystemServer(t, deps)
	status, _ := getConfig(t, ts.URL)
	if status != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500", status)
	}
}

// SystemDeps is exported and has no constructor, so an out-of-tree caller can
// build one without the OAuth provider that was added for notices. The nil
// path has to yield no notices rather than an empty scope: operatorNotices
// cannot tell "not configured" from "no provider wired", so feeding it "" puts
// a permanent "set oauth.default_client_scope" banner in front of a caller who
// may already have set it, with no way to clear it.
func TestSystemConfig_NilOAuthProvider_EmitsNoNotices(t *testing.T) {
	deps := staticSystemDeps()
	deps.OAuth = nil
	// dcr.mode open is the combination that would otherwise raise the notice.
	deps.DCRMode = static.NewDCRModeProvider("open", nil)

	ts := newSystemServer(t, deps)
	status, body := getConfig(t, ts.URL)
	if status != http.StatusOK {
		t.Fatalf("status: got %d, want 200 — a missing advisory provider must not 500", status)
	}
	notices, ok := body["notices"].([]any)
	if !ok {
		t.Fatalf("notices: got %T, want an array", body["notices"])
	}
	if len(notices) != 0 {
		t.Fatalf("notices: got %v, want none when the OAuth provider is absent", notices)
	}
}
