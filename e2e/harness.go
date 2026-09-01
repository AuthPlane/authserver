//go:build e2e

// Package e2e provides end-to-end test infrastructure for authserver.
package e2e

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	apiadmin "github.com/authplane/authserver/api/admin"
	apipublic "github.com/authplane/authserver/api/public"
	"github.com/authplane/authserver/internal/adapters/aesmaster"
	brokerprotoapikey "github.com/authplane/authserver/internal/adapters/brokerproto/apikey"
	brokerprotooauth "github.com/authplane/authserver/internal/adapters/brokerproto/oauth"
	brokerprotoserviceaccount "github.com/authplane/authserver/internal/adapters/brokerproto/serviceaccount"
	"github.com/authplane/authserver/internal/adapters/cache"
	"github.com/authplane/authserver/internal/adapters/cimd"
	"github.com/authplane/authserver/internal/adapters/idpjwks"
	"github.com/authplane/authserver/internal/adapters/keyfile"
	"github.com/authplane/authserver/internal/adapters/sqlite"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/adapters/storage"
	"github.com/authplane/authserver/internal/brokerproto"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain/idp"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
)

// testAESKeyHex is a fixed 32-byte AES key for E2E tests (hex-encoded).
const testAESKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// testStateSecret is a fixed HMAC key for connection PKCE state tokens in E2E tests.
var testStateSecret = []byte("e2e-test-state-secret-32-bytes!!")

// TestHarness provides a full authserver server and MCP resource server for E2E tests.
type TestHarness struct {
	T          *testing.T
	AuthServer *httptest.Server // authserver server
	Issuer     string           // AuthServer URL (acts as issuer)
	AdminSvc   *services.AdminService
	obs        *observability.Provider

	// Unified resource admin service (always available — DB-backed).
	// The legacy ResourceServerSvc / AllowlistSvc / ConnectorConfigSvc
	// fields are gone alongside their admin surfaces; tests that
	// previously used those services now go through ResourceAdminSvc.
	ResourceAdminSvc *services.ResourceAdminService

	// AdminAPI is the admin HTTP server, populated when
	// HarnessConfig.EnableAdminAPI is true. This lets
	// scenarios exercise /admin/resources, /admin/broker-providers,
	// /admin/grants, /admin/issuances, and /admin/audit through real HTTP
	// (the public AS server runs on a different port and does not expose
	// these endpoints). Tests use AdminRequest to issue authenticated
	// requests with AdminAPIKey pre-set.
	AdminAPI    *httptest.Server
	AdminAPIKey string

	// Internal stores for test helpers.
	clientStore   output.ClientStore
	issuanceStore output.IssuanceStore

	// XAA fields (nil when XAA is not enabled).
	xaaIDPSvc       *services.XAAIDPService
	xaaPolicySvc    *services.XAAPolicyService
	subjectMapSvc   *services.SubjectMappingService
	idpStore        output.IDPStore
	xaaPolicyStore  output.XAAPolicyStore
	subjectMapStore output.SubjectMappingStore

	// Upstream-connection fixtures (nil when token exchange is disabled).
	encryptor           output.DataEncryptor
	resourceStore       output.ResourceStore
	brokerProviderStore output.BrokerProviderStore
	brokerGrantStore    output.BrokerGrantStore
	consentGrantStore   output.ConsentGrantStore
	// mockUpstreamURLs maps provider slug → mock upstream base URL,
	// populated when hcfg.Connectors is set. SeedConnection reads it to
	// populate broker_providers.config_data.token_url with a stub the
	// brokerproto/oauth adapter can call.
	mockUpstreamURLs map[string]string
	// mockUpstreamRequests captures per-provider authorize-time and
	// token-time form data so e2e scenarios can assert RFC 6749 §4.1.3
	// `redirect_uri` propagation across the full HTTP roundtrip. Keyed by
	// provider slug; each value is appended in arrival order.
	mockUpstreamRequests map[string]*mockUpstreamRecorder
}

// mockUpstreamRecorder captures observed authorize and token requests at the
// mock upstream provider so tests can assert what the AS sent over the wire.
type mockUpstreamRecorder struct {
	mu             sync.Mutex
	authorizeQuery []url.Values // GET /authorize query params
	tokenForm      []url.Values // POST /token form body
}

// AuthorizeRequests returns a copy of the recorded /authorize query strings
// for the given provider slug. Empty if the upstream was never hit.
func (h *TestHarness) AuthorizeRequests(providerSlug string) []url.Values {
	rec, ok := h.mockUpstreamRequests[providerSlug]
	if !ok {
		return nil
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	out := make([]url.Values, len(rec.authorizeQuery))
	copy(out, rec.authorizeQuery)
	return out
}

// TokenRequests returns a copy of the recorded /token form bodies for the
// given provider slug.
func (h *TestHarness) TokenRequests(providerSlug string) []url.Values {
	rec, ok := h.mockUpstreamRequests[providerSlug]
	if !ok {
		return nil
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	out := make([]url.Values, len(rec.tokenForm))
	copy(out, rec.tokenForm)
	return out
}

// harnessSecretResolver implements the brokerproto SecretResolver surface for
// tests by returning a fixed dummy client_secret regardless of the secret
// reference. The mock upstream does not validate the secret, so a constant
// value suffices and keeps E2E setup zero-config (no env-var plumbing per
// service in each test file). Production uses the os.Getenv-backed
// resolver in cmd/authserver/serve.go::envSecretResolver.
//
// The legacy `os` import is retained for tests that set their own env
// vars directly; this struct intentionally does not call os.Getenv.
type harnessSecretResolver struct{}

// Resolve returns the fixed test client_secret. ctx and src are ignored.
func (harnessSecretResolver) Resolve(_ context.Context, _ output.SecretSource) (string, error) {
	return "harness-mock-client-secret", nil
}

// harnessSessionSecret is the e2e output.SessionSecretProvider. NewServer now
// requires Deps.SessionSecretProvider (no silent ephemeral fallback), so the
// harness supplies a fixed secret for every call.
type harnessSessionSecret struct{}

// Secret returns the fixed E2E session secret. ctx is ignored.
func (harnessSessionSecret) Secret(_ context.Context) ([]byte, error) {
	return []byte("e2e-test-session-secret-32-byte!"), nil
}

// _ keeps the os import live (used by direct os.Setenv calls in some
// scenario tests that probe env-var-driven config paths).
var _ = os.Getenv

// HarnessConfig configures the test harness.
type HarnessConfig struct {
	DCRMode           string
	ApprovedRedirects []string
	Resources         []config.ResourceConfigUnified
	RateLimit         *config.RateLimitConfig
	// Connectors enables upstream-connection support with these connectors.
	// Each entry creates a mock upstream OAuth provider.
	Connectors []ConnectorConfig
	// EnableClientCredentials enables the client_credentials grant.
	EnableClientCredentials bool
	// EnableTokenExchange enables the token exchange grant (RFC 8693).
	EnableTokenExchange bool
	// TokenExchangeAllowSelfExchange allows self-exchange when token exchange is enabled.
	TokenExchangeAllowSelfExchange bool
	// TokenExchangeMaxChainDepth sets the max delegation chain depth (default 5).
	TokenExchangeMaxChainDepth int
	// EnableDPoP enables DPoP proof-of-possession (RFC 9449).
	EnableDPoP bool

	// EnableXAA enables Enterprise-Managed Authorization (JWT Bearer + Policy Engine).
	EnableXAA bool
	// XAASubjectMode controls subject mapping: "auto_map" (default) or "strict".
	XAASubjectMode string
	// XAARequireResource refuses jwt-bearer exchanges that name no resource,
	// on the assertion or the request (xaa.require_resource).
	XAARequireResource bool

	// EnableAdminAPI starts the admin HTTP server alongside
	// the public AS so scenarios can drive /admin/resources,
	// /admin/broker-providers, /admin/grants, /admin/issuances and
	// /admin/audit end-to-end. The server is reachable via h.AdminAPI;
	// h.AdminAPIKey is the bearer token. Wires the same unified-resource
	// admin services serve.go constructs in production.
	EnableAdminAPI bool
}

// ConnectorConfig configures a mock upstream connector for E2E connection tests.
type ConnectorConfig struct {
	Service      string   // e.g. "github"
	Scopes       []string // scopes the mock provider grants
	AccessToken  string   // token the mock provider returns
	RefreshToken string   // refresh token the mock returns (optional)
	ExpiresIn    int      // token TTL in seconds (0 = non-expiring)
}

// NewTestHarness creates a fully-wired authserver httptest.Server.
func NewTestHarness(t *testing.T, hcfg HarnessConfig) *TestHarness {
	t.Helper()

	obs := observability.NewNoop()
	if os.Getenv("E2E_DEBUG") != "" {
		obs.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	// 1. In-memory SQLite with migrations.
	db, err := sqlite.Open(":memory:", obs)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		db.Close()
		t.Fatalf("migrate test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	stores := db.NewStores()

	// front the user store with the same TTL cache production uses
	// (cmd/authserver/serve.go applies storage.WithUserCache to its DataStore).
	// Pass userStore to every service and the SessionMiddleware so admin
	// Update/Delete invalidations propagate to the stale-session check, and
	// reads ride the cache uniformly.
	userStore := storage.WrapUserStore(stores.User, cache.NewMemoryTTLBounded[*storage.Entry](60*time.Second, 1024))

	// 2. Key store (temp dir).
	keyDir := t.TempDir()
	keyStore, err := keyfile.New(keyDir, obs.WithComponent("keyfile"))
	if err != nil {
		t.Fatalf("create key store: %v", err)
	}

	// 3. Services — mirrors cmd/authserver/main.go runServe() exactly.
	jwksSvc := services.NewJWKSService(keyStore, cache.NewMemory[*jose.JSONWebKeySet](), "ES256", obs.WithComponent("jwks"))
	auditSvc := services.NewAuditService(stores.Audit, obs.WithComponent("audit"))

	dcrMode := hcfg.DCRMode
	if dcrMode == "" {
		dcrMode = "open"
	}

	cimdFetcher := cimd.New(obs.WithComponent("cimd"))
	cimdFetcher.SetAllowLoopback(true) // E2E tests use httptest servers on loopback.
	dcrModeProvider := static.NewDCRModeProvider(dcrMode, hcfg.ApprovedRedirects)

	// compute the runtime-enabled grant set so admin + DCR + CIMD
	// reject registrations asking for grants the AS isn't configured to
	// honor. Mirrors config.EnabledGrantTypes; the harness builds it from
	// HarnessConfig flags (no full Config struct).
	enabledGrants := []string{"authorization_code", "refresh_token"}
	if hcfg.EnableClientCredentials {
		enabledGrants = append(enabledGrants, "client_credentials")
	}
	if hcfg.EnableTokenExchange {
		enabledGrants = append(enabledGrants, "urn:ietf:params:oauth:grant-type:token-exchange")
	}
	if hcfg.EnableXAA {
		enabledGrants = append(enabledGrants, "urn:ietf:params:oauth:grant-type:jwt-bearer")
	}
	grantsProvider := static.NewEnabledGrantsProvider(enabledGrants)

	// Shared config providers consumed by both the feature services and the AS
	// metadata discovery document (built into asMetadataSvc before srvReal).
	// E2E uses loopback httptest servers, so RequireHTTPS=false.
	cimdConfigProvider := static.NewCIMDConfigProvider(output.CIMDConfig{
		Enabled:      true,
		RequireHTTPS: false,
		CacheTTL:     5 * time.Minute,
		FetchTimeout: 10 * time.Second,
	})
	oauthConfigProvider := static.NewOAuthConfigProvider(output.OAuthConfig{
		RequireScope:         false,
		IntrospectionEnabled: true,
	})
	agentsConfigProvider := static.NewAgentsConfigProvider(output.AgentsConfig{
		AgentIdentityEnabled: true,
	})
	dpopConfigProvider := static.NewDPoPConfigProvider(output.DPoPConfig{
		Enabled:       hcfg.EnableDPoP,
		ProofLifetime: 60 * time.Second,
		RequireNonce:  false,
		NonceTTL:      60 * time.Second,
	})

	cimdSvc := services.NewCIMDService(
		stores.Client, cimdFetcher, dcrModeProvider,
		cimdConfigProvider,
		obs.WithComponent("cimd-svc"),
		services.WithCIMDEnabledGrants(grantsProvider),
	)

	dcrSvc := services.NewDCRService(
		stores.Client,
		dcrModeProvider,
		obs.WithComponent("dcr"), auditSvc,
		services.WithDCREnabledGrants(grantsProvider),
	)

	authSvc := services.NewUserAuthService(userStore, obs.WithComponent("auth"), auditSvc)

	// Seed config-defined resources into the resource_servers table so the
	// dynamic lister (below) picks them up alongside any resource servers
	// registered at test time. The legacy resource_servers store survives
	// : the unified Resource registry replaces the legacy resource_servers
	// dynamic lister. Seed loop below populates the resources table; the
	// registry reads from it on every call.
	resourceRegistry := services.NewResourceRegistry(
		stores.Resource, stores.BrokerProvider, obs.WithComponent("resource-registry"),
	)
	resourceLister := resourceRegistry

	// brokerproto adapters wire unconditionally ( registry-or-bust).
	bpRegistry := brokerproto.NewRegistry()
	bpHTTPClient := &http.Client{Timeout: 10 * time.Second}
	if regErr := bpRegistry.Register(brokerprotooauth.New(
		bpHTTPClient, harnessSecretResolver{}, brokerprotooauth.WithAllowLoopback(true),
	)); regErr != nil {
		t.Fatalf("register brokerproto/oauth adapter: %v", regErr)
	}
	if regErr := bpRegistry.Register(brokerprotoapikey.New(harnessSecretResolver{})); regErr != nil {
		t.Fatalf("register brokerproto/apikey adapter: %v", regErr)
	}
	if regErr := bpRegistry.Register(brokerprotoserviceaccount.New(
		bpHTTPClient, harnessSecretResolver{},
	)); regErr != nil {
		t.Fatalf("register brokerproto/serviceaccount adapter: %v", regErr)
	}

	authzSvc := services.NewAuthorizeService(
		stores.Client, stores.Session, stores.ConsentGrant,
		cimdSvc, resourceRegistry,
		oauthConfigProvider,
		obs.WithComponent("authorize"),
	)

	consentSvc := services.NewConsentService(
		stores.ConsentGrant, stores.Session, stores.Client, resourceRegistry,
		obs.WithComponent("consent"), auditSvc,
	)

	tokenConfigProvider := static.NewTokenConfigProvider(output.TokenConfig{
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 24 * time.Hour,
	})

	// Use a placeholder issuer; we'll update it after the server starts.
	mintIssuerPlaceholder := services.NewMintIssuer(jwksSvc, stores.Issuance, static.NewIssuerProvider("http://placeholder"), obs.WithComponent("mint-issuer"))
	tokenSvc := services.NewTokenService(
		stores.Session, stores.Token, stores.Client, userStore,
		jwksSvc, mintIssuerPlaceholder, tokenConfigProvider,
		obs.WithComponent("token"), auditSvc,
		stores.Revocation, resourceLister,
	)

	revokeSvc := services.NewRevocationService(stores.Token, stores.Client, stores.MachineToken, jwksSvc, static.NewIssuerProvider("http://placeholder"), obs.WithComponent("revoke"), auditSvc, stores.Revocation)

	// Introspection service — use placeholder issuer, will be rebuilt.
	introspectSvc := services.NewIntrospectionService(
		jwksSvc, stores.Revocation, stores.MachineToken, stores.Client, userStore,
		static.NewIssuerProvider("http://placeholder"), obs.WithComponent("introspect"), auditSvc,
	)
	introspectSvc.WithResourceRegistry(resourceRegistry)

	adminSvc := services.NewAdminService(
		stores.Client, userStore, stores.Token, stores.Audit,
		obs.WithComponent("admin"), auditSvc,
		services.WithMachineTokenStore(stores.MachineToken),
		services.WithRevocationStore(stores.Revocation),
		services.WithEnabledGrants(grantsProvider),
	)

	// Fronting-link service. Constructed
	// once so the runtime token-exchange path, the admin surface, AND the
	// resource-admin's edit-time + cascade validators all share a single
	// instance (production wiring in cmd/authserver/serve.go does the same).
	frontingAdminSvc := services.NewFrontingService(
		stores.FrontingLink, stores.Resource, stores.TransactionMgr,
		obs.WithComponent("fronting-admin"), auditSvc,
	)

	// Unified Resource admin service — always available, DB-backed.
	// Replaces the legacy ResourceServerService retired in .
	resourceAdminSvc := services.NewResourceAdminService(
		stores.Resource, stores.BrokerProvider, stores.Client,
		obs.WithComponent("resource-admin"), auditSvc,
		services.WithFrontingValidator(frontingAdminSvc),
	)

	// Seed the unified resources table from hcfg.Resources. Skip-on-existing.
	for _, r := range hcfg.Resources {
		dom, err := harnessResourceConfigToDomain(r)
		if err != nil {
			t.Fatalf("seed unified resource %q: %v", r.Slug, err)
		}
		if existing, getErr := stores.Resource.GetBySlug(context.Background(), r.Slug); getErr == nil && existing != nil {
			continue
		}
		if err := resourceAdminSvc.Create(context.Background(), dom); err != nil {
			t.Fatalf("seed unified resource %q: %v", r.Slug, err)
		}
	}

	// Client credentials service (optional).
	var clientCredsSvc *services.ClientCredentialsService
	if hcfg.EnableClientCredentials {
		clientCredsSvc = services.NewClientCredentialsService(
			stores.Client, stores.MachineToken, jwksSvc,
			static.NewIssuerProvider("http://placeholder"), static.NewClientCredentialsConfigProvider(output.ClientCredentialsConfig{TokenExpiry: 1 * time.Hour}),
			obs.WithComponent("client-credentials"), auditSvc,
			resourceLister,
		)
	}

	// 3b. Agent identity service — always enabled.
	agentIdentitySvc := services.NewAgentIdentityService(stores.Client, obs.WithComponent("agent-identity"))
	if clientCredsSvc != nil {
		clientCredsSvc.WithAgentIdentity(agentIdentitySvc)
	}

	// 4. Upstream-connection services (optional). The legacy VendService and
	// MapResolver are gone; ConnectService dispatches through brokerproto.
	var connectSvc *services.ConnectService
	var encryptor output.DataEncryptor
	// mockUpstreamURLs captures each per-provider mock-upstream base URL so
	// SeedConnection can populate the BrokerProvider's config_data.token_url
	// with a stub the brokerproto/oauth adapter can actually call.
	mockUpstreamURLs := make(map[string]string)
	mockUpstreamRequests := make(map[string]*mockUpstreamRecorder)

	if len(hcfg.Connectors) > 0 {
		enc, err := aesmaster.New(testAESKeyHex, obs.WithComponent("aesmaster"))
		if err != nil {
			t.Fatalf("create test encryptor: %v", err)
		}
		encryptor = enc
		for _, vc := range hcfg.Connectors {
			recorder := &mockUpstreamRecorder{}
			mockUpstreamRequests[vc.Service] = recorder
			mock := newMockUpstreamProvider(t, vc, recorder)
			mockUpstreamURLs[vc.Service] = mock.URL
		}
	}

	// 5. HTTP server.
	serverCfg := config.ServerConfig{
		Issuer: "http://placeholder",
	}

	rlCfg := config.RateLimitConfig{}
	if hcfg.RateLimit != nil {
		rlCfg = *hcfg.RateLimit
	}

	deps := apipublic.Deps{
		URLs:                  static.NewURLBuilder(),
		JWKS:                  jwksSvc,
		DCR:                   dcrSvc,
		Auth:                  authSvc,
		Authorize:             authzSvc,
		Consent:               consentSvc,
		Token:                 tokenSvc,
		Revoke:                revokeSvc,
		Introspect:            introspectSvc,
		OAuthConfig:           oauthConfigProvider,
		Health:                db,
		SessionSecretProvider: harnessSessionSecret{},
		SessionConfigProvider: static.NewSessionConfigProvider(output.SessionConfig{
			MaxAge:   24 * time.Hour,
			SameSite: http.SameSiteLaxMode,
		}),
		OIDCStateConfigProvider: static.NewOIDCStateConfigProvider(output.OIDCStateConfig{
			MaxAge: 10 * time.Minute,
		}),
		SessionCookie: apipublic.SessionCookie{},
		RateLimitCfg:  rlCfg,
		LoginDisplay:  static.NewLoginDisplayProvider(config.OIDCConfig{ShowLocalLogin: true}),
		// have SessionMiddleware reject session cookies whose userID
		// no longer exists in the user store. Same shared instance the
		// services use (see userStore above) so admin Update/Delete
		// invalidations propagate to the stale-session check.
		Users: userStore,
		// Placeholder satisfies the oauth handlers at construction time; it is
		// overwritten with the real ts.URL value before the second
		// apipublic.NewServer call that actually backs test scenarios. The AS
		// metadata discovery routes are only registered on that second server
		// (deps.ASMetadata is wired there), so no issuer placeholder is needed.
		IssuerProvider: static.NewIssuerProvider("http://placeholder"),
		// CORS allowed-origins provider is required by NewServer. serverCfg sets
		// no AllowedOrigins, so this is CORS-disabled — matching the harness's
		// pre-seam behavior.
		CORSConfigProvider: static.NewCORSConfigProvider(serverCfg.AllowedOrigins),
	}
	// Avoid typed-nil → interface assignment (Go interface nil gotcha).
	if clientCredsSvc != nil {
		deps.ClientCredentials = clientCredsSvc
	}
	srv := apipublic.NewServer(context.Background(), serverCfg, deps, obs.WithComponent("http"))

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// 5. Now that we know the URL, re-create services with correct issuer.
	// The token/introspection services use issuer for JWT claims. We need it to match.
	mintIssuerReal := services.NewMintIssuer(jwksSvc, stores.Issuance, static.NewIssuerProvider(ts.URL), obs.WithComponent("mint-issuer"))
	tokenSvcReal := services.NewTokenService(
		stores.Session, stores.Token, stores.Client, userStore,
		jwksSvc, mintIssuerReal, tokenConfigProvider,
		obs.WithComponent("token"), auditSvc,
		stores.Revocation, resourceLister,
	)
	// mirror cmd/authserver/serve.go so the auth-code and
	// refresh-token grants persist their issuances audit row in the e2e
	// harness, not only in production. Without this, /admin/issuances
	// stays empty for every Mint token issued via the standard OAuth
	// grants under test.
	tokenSvcReal.WithResourceRegistry(resourceRegistry)
	introspectSvcReal := services.NewIntrospectionService(
		jwksSvc, stores.Revocation, stores.MachineToken, stores.Client, userStore,
		static.NewIssuerProvider(ts.URL), obs.WithComponent("introspect"), auditSvc,
	)
	// mirror cmd/authserver/serve.go so a resource server may introspect a
	// token minted for it.
	introspectSvcReal.WithResourceRegistry(resourceRegistry)
	revokeSvcReal := services.NewRevocationService(stores.Token, stores.Client, stores.MachineToken, jwksSvc, static.NewIssuerProvider(ts.URL), obs.WithComponent("revoke"), auditSvc, stores.Revocation)
	serverCfg.Issuer = ts.URL

	// Rebuild with correct issuer.
	deps.Token = tokenSvcReal
	deps.Introspect = introspectSvcReal
	deps.Revoke = revokeSvcReal

	var clientCredsSvcReal *services.ClientCredentialsService
	if hcfg.EnableClientCredentials {
		clientCredsSvcReal = services.NewClientCredentialsService(
			stores.Client, stores.MachineToken, jwksSvc,
			static.NewIssuerProvider(ts.URL), static.NewClientCredentialsConfigProvider(output.ClientCredentialsConfig{TokenExpiry: 1 * time.Hour}),
			obs.WithComponent("client-credentials"), auditSvc,
			resourceLister,
		)
		clientCredsSvcReal.WithAgentIdentity(agentIdentitySvc)
		// emit per-token issuance audit rows for the admin
		// /admin/issuances list (mirrors cmd/authserver/serve.go).
		clientCredsSvcReal.WithIssuanceAudit(stores.Issuance, resourceRegistry)
		deps.ClientCredentials = clientCredsSvcReal
	}

	// BrokerIssuer + ConnectService both need a DataEncryptor; configurations
	// that don't supply one via Connectors still need it for SeedConnection.
	if encryptor == nil {
		enc, err := aesmaster.New(testAESKeyHex, obs.WithComponent("aesmaster"))
		if err != nil {
			t.Fatalf("create test encryptor: %v", err)
		}
		encryptor = enc
	}
	brokerIssuer := services.NewBrokerIssuer(
		stores.BrokerGrant, encryptor, stores.Issuance,
		bpRegistry,
		obs.WithComponent("broker-issuer"), auditSvc,
	)

	var tokenExchangeSvcReal *services.TokenExchangeService
	if hcfg.EnableTokenExchange {
		maxDepth := hcfg.TokenExchangeMaxChainDepth
		if maxDepth == 0 {
			maxDepth = 5
		}
		tokenExchangeSvcReal = services.NewTokenExchangeService(
			stores.Client, stores.MachineToken, jwksSvc, jwksSvc,
			stores.Revocation, static.NewIssuerProvider(ts.URL),
			static.NewTokenExchangeConfigProvider(output.TokenExchangeConfig{
				AllowSelfExchange: hcfg.TokenExchangeAllowSelfExchange,
				MaxChainDepth:     maxDepth,
				TokenExpiry:       1 * time.Hour,
			}),
			resourceRegistry, stores.ConsentGrant, mintIssuerReal, brokerIssuer,
			obs.WithComponent("token-exchange"), auditSvc,
		)
		tokenExchangeSvcReal.WithAgentIdentity(agentIdentitySvc)
		tokenExchangeSvcReal.WithResourceScopes(resourceLister)
		tokenExchangeSvcReal.WithFronting(frontingAdminSvc)
		deps.TokenExchange = tokenExchangeSvcReal
	}

	// IssuerProvider powers both consent_url flavors emitted by the oauth
	// handler's writeTokenError: the bound-B / bound-C AS-side re-consent URL
	// (/authorize?resource=<mcp_slug>&scope=<missing>) and the bound-D /
	// bound-E broker upstream re-connect URL (/connect/<provider>). Without
	// it those flows emit an empty consent_url.
	deps.IssuerProvider = static.NewIssuerProvider(ts.URL)

	// ConnectService — wired whenever the harness has a state secret + an
	// encryptor (always true now since BrokerIssuer needs an
	// encryptor). The new ConnectService dispatches via brokerproto.
	if len(hcfg.Connectors) > 0 {
		connectSvc = services.NewConnectService(
			resourceRegistry, stores.Resource, stores.BrokerProvider, stores.BrokerGrant, stores.ConnectPendingState,
			bpRegistry, encryptor,
			static.NewConnectStateConfigProvider(testStateSecret),
			static.NewIssuerProvider(ts.URL),
			static.NewConnectConfigProvider(output.ConnectConfig{RedirectBaseURL: ts.URL}),
			obs.WithComponent("connect"), auditSvc,
		)
		deps.Connect = connectSvc
	}

	// Wire DPoP proof-of-possession (RFC 9449) if enabled.
	if hcfg.EnableDPoP {
		tokenSvcReal.WithDPoP(stores.DPoPNonce, dpopConfigProvider)
		if clientCredsSvcReal != nil {
			clientCredsSvcReal.WithDPoP(stores.DPoPNonce, dpopConfigProvider)
		}
		if tokenExchangeSvcReal != nil {
			tokenExchangeSvcReal.WithDPoP(stores.DPoPNonce, dpopConfigProvider)
		}
		deps.DPoPNonce = stores.DPoPNonce
		deps.DPoPCfg = config.DPoPConfig{
			Enabled:       true,
			NonceTTL:      60 * time.Second,
			ProofLifetime: 60 * time.Second,
			RequireNonce:  false,
		}
	}

	// Wire XAA (Enterprise-Managed Authorization) if enabled.
	var xaaIDPSvc *services.XAAIDPService
	var xaaPolicySvc *services.XAAPolicyService
	var subjectMappingSvc *services.SubjectMappingService
	if hcfg.EnableXAA {
		// The SSRF-safe client blocks loopback, so the harness injects a plain
		// one. Test-only — see idpjwks.WithHTTPClient.
		xaaJWKSCache := idpjwks.New(stores.IDP, cache.NewMemory[*idpjwks.Entry](), idpjwks.CacheConfig{TTL: 5 * time.Minute}, obs.WithComponent("idp-jwks"),
			idpjwks.WithHTTPClient(&http.Client{Timeout: 10 * time.Second}))

		xaaIDPSvc = services.NewXAAIDPService(
			stores.IDP, xaaJWKSCache, idpjwks.DiscoverJWKSUri,
			static.NewIssuerProvider(ts.URL), obs.WithComponent("xaa-idp"), auditSvc,
		)

		subjectMode := hcfg.XAASubjectMode
		if subjectMode == "" {
			subjectMode = "auto_map"
		}
		jwtBearerSvc := services.NewJWTBearerService(
			stores.IDP, xaaJWKSCache, stores.AssertionJTI,
			stores.Client, stores.MachineToken, jwksSvc,
			static.NewIssuerProvider(ts.URL),
			static.NewXAAConfigProvider(output.XAAConfig{
				TokenExpiry:     1 * time.Hour,
				MaxAssertionAge: 5 * time.Minute,
				SubjectMode:     subjectMode,
				RequireResource: hcfg.XAARequireResource,
			}),
			obs.WithComponent("jwt-bearer"), auditSvc,
			resourceLister,
		)
		jwtBearerSvc.WithAgentIdentity(agentIdentitySvc)
		// emit per-token issuance audit rows for the admin
		// /admin/issuances list (mirrors cmd/authserver/serve.go).
		jwtBearerSvc.WithIssuanceAudit(stores.Issuance, resourceRegistry)

		xaaPolicySvc = services.NewXAAPolicyService(
			stores.XAAPolicy, stores.IDP,
			obs.WithComponent("xaa-policy"), auditSvc,
		)
		subjectMappingSvc = services.NewSubjectMappingService(
			stores.SubjectMapping, stores.IDP,
			obs.WithComponent("subject-mapping"),
		)

		jwtBearerSvc.WithPolicy(xaaPolicySvc, subjectMappingSvc)

		if hcfg.EnableDPoP {
			jwtBearerSvc.WithDPoP(stores.DPoPNonce, static.NewDPoPConfigProvider(output.DPoPConfig{
				Enabled:       true,
				ProofLifetime: 60 * time.Second,
				RequireNonce:  false,
				NonceTTL:      60 * time.Second,
			}))
		}

		deps.JWTBearer = jwtBearerSvc
	}

	// AS metadata discovery assembler, built with the real issuer (ts.URL) and
	// the shared static providers. Discovery routes are registered only on the
	// real server below (deps.ASMetadata is non-nil here).
	deps.ASMetadata = services.NewASMetadataService(
		static.NewIssuerProvider(ts.URL),
		grantsProvider,
		cimdConfigProvider,
		dpopConfigProvider,
		oauthConfigProvider,
		agentsConfigProvider,
		resourceLister,
		obs.WithComponent("as-metadata"),
	)

	srvReal := apipublic.NewServer(context.Background(), serverCfg, deps, obs.WithComponent("http"))
	// Replace handler on the test server.
	ts.Config.Handler = srvReal.Handler()

	// : optional admin HTTP server. Mirrors the wiring in
	// cmd/authserver/serve.go so /admin/{resources,broker-providers,grants,issuances,audit}
	// behave identically to a live binary. Constructed last because the
	// admin DTOs accept the existing ResourceAdminService (already built
	// above) plus the broker-provider / grant / issuance services we
	// instantiate here for the first time in this harness.
	var adminTS *httptest.Server
	const harnessAdminAPIKey = "harness-admin-api-key"
	if hcfg.EnableAdminAPI {
		brokerProviderAdminSvc := services.NewBrokerProviderAdminService(
			stores.BrokerProvider, obs.WithComponent("broker-provider-admin"), auditSvc,
			static.NewConfigSecretBackend(nil),
		)
		grantAdminSvc := services.NewGrantAdminService(
			stores.ConsentGrant, stores.BrokerGrant, stores.Issuance,
			obs.WithComponent("grant-admin"), auditSvc,
		)
		issuanceAdminSvc := services.NewIssuanceAdminService(
			stores.Issuance, obs.WithComponent("issuance-admin"), auditSvc,
		)
		adminSrv, err := apiadmin.NewServer(
			context.Background(),
			config.AdminConfig{Enabled: true, Address: ":0", APIKey: harnessAdminAPIKey},
			adminSvc,
			obs.WithComponent("admin-http"),
			apiadmin.OptionalDeps{
				Resources:       &apiadmin.ResourceAdminDeps{Resources: resourceAdminSvc},
				BrokerProviders: &apiadmin.BrokerProviderAdminDeps{BrokerProviders: brokerProviderAdminSvc},
				Grants:          &apiadmin.GrantAdminDeps{Grants: grantAdminSvc},
				Issuances:       &apiadmin.IssuanceAdminDeps{Issuances: issuanceAdminSvc},
				Fronting:        &apiadmin.FrontingAdminDeps{Fronting: frontingAdminSvc},
			},
		)
		if err != nil {
			t.Fatalf("admin server: %v", err)
		}
		adminTS = httptest.NewServer(adminSrv.Handler())
		t.Cleanup(adminTS.Close)
	}

	h := &TestHarness{
		T:                    t,
		AuthServer:           ts,
		Issuer:               ts.URL,
		AdminSvc:             adminSvc,
		ResourceAdminSvc:     resourceAdminSvc,
		AdminAPI:             adminTS,
		AdminAPIKey:          harnessAdminAPIKey,
		obs:                  obs,
		clientStore:          stores.Client,
		issuanceStore:        stores.Issuance,
		encryptor:            encryptor,
		resourceStore:        stores.Resource,
		brokerProviderStore:  stores.BrokerProvider,
		brokerGrantStore:     stores.BrokerGrant,
		consentGrantStore:    stores.ConsentGrant,
		mockUpstreamURLs:     mockUpstreamURLs,
		mockUpstreamRequests: mockUpstreamRequests,
	}

	if hcfg.EnableXAA {
		h.xaaIDPSvc = xaaIDPSvc
		h.xaaPolicySvc = xaaPolicySvc
		h.subjectMapSvc = subjectMappingSvc
		h.idpStore = stores.IDP
		h.xaaPolicyStore = stores.XAAPolicy
		h.subjectMapStore = stores.SubjectMapping
	}

	return h
}

// SetupE2E creates a harness and one or more resource servers in a single call.
// It handles the two-phase setup: resource servers are created first (getting stable URLs),
// then the harness is created with those URLs in its resource config, and the resource servers
// are updated to point at the harness's auth server URL.
func SetupE2E(t *testing.T, hcfg HarnessConfig, resourceScopes ...[]string) (*TestHarness, []*MCPResourceServer) {
	t.Helper()

	// Phase 1: create resource servers (they get stable httptest URLs).
	var servers []*MCPResourceServer
	for _, scopes := range resourceScopes {
		rs := NewMCPResourceServer(t, scopes)
		servers = append(servers, rs)
	}

	// Phase 2: build resource config with real RS URIs.
	resources := make([]config.ResourceConfigUnified, len(servers))
	for i, rs := range servers {
		slug := fmt.Sprintf("mcp-%d", i)
		display := slug
		if i < len(hcfg.Resources) && hcfg.Resources[i].Slug != "" {
			slug = hcfg.Resources[i].Slug
		}
		if i < len(hcfg.Resources) && hcfg.Resources[i].DisplayName != "" {
			display = hcfg.Resources[i].DisplayName
		}
		scopeNames := resourceScopes[i]
		scopes := make([]config.ScopeConfig, len(scopeNames))
		for j, sn := range scopeNames {
			scopes[j] = config.ScopeConfig{Name: sn}
		}
		if i < len(hcfg.Resources) && len(hcfg.Resources[i].Scopes) > 0 {
			scopes = hcfg.Resources[i].Scopes
		}
		resources[i] = config.ResourceConfigUnified{
			Slug:        slug,
			URI:         rs.URI,
			BackendKind: string(resource.BackendMint),
			DisplayName: display,
			Scopes:      scopes,
		}
	}
	hcfg.Resources = resources

	// Phase 3: create harness with correct resource URIs.
	h := NewTestHarness(t, hcfg)

	// Phase 4: update resource servers to point at the harness.
	for _, rs := range servers {
		rs.SetAuthServer(h.Issuer)
	}

	return h, servers
}

// harnessResourceConfigToDomain mirrors the production
// resourceConfigUnifiedToDomain helper but skips the broker-provider-slug
// resolution (E2E tests that need Broker resources go through the existing
// SeedConnection helpers rather than the harness-config seed loop, so all
// hcfg.Resources entries are Mint).
func harnessResourceConfigToDomain(r config.ResourceConfigUnified) (*resource.Resource, error) {
	kind := resource.BackendKind(r.BackendKind)
	if kind == "" {
		kind = resource.BackendMint
	}
	if kind != resource.BackendMint {
		return nil, fmt.Errorf("harness Resources[%q]: only mint resources supported, got backend_kind=%q", r.Slug, r.BackendKind)
	}
	scopes := make([]resource.Scope, len(r.Scopes))
	for i, sc := range r.Scopes {
		scopes[i] = resource.Scope{
			Name:        sc.Name,
			Description: sc.Description,
			Upstream:    sc.Upstream,
		}
	}
	display := r.DisplayName
	if display == "" {
		display = r.Slug
	}
	return &resource.Resource{
		Slug:        r.Slug,
		DisplayName: display,
		URI:         r.URI,
		BackendKind: kind,
		Scopes:      scopes,
		Policy: resource.Policy{
			Exchange: resource.ExchangePolicy{
				AllowedClientIDs: r.Policy.Exchange.AllowedClientIDs,
			},
			Connect: resource.ConnectPolicy{
				AllowedReturnURLs: r.Policy.Connect.AllowedReturnURLs,
			},
		},
	}, nil
}

// deletion: SeedMintResource removed. Tests register Mint
// resources via h.AdminCreateResource (e2e/admin_helpers.go), driving
// the same admin endpoint an operator following the docs would call.

// CreateUser creates a test user and returns their ID.
func (h *TestHarness) CreateUser(email, password string) string {
	h.T.Helper()
	u, err := h.AdminSvc.CreateUser(context.Background(), input.CreateUserRequest{
		Email:    email,
		Password: password,
		Role:     user.RoleUser,
	})
	if err != nil {
		h.T.Fatalf("create user: %v", err)
	}
	return u.ID
}

// RegisterScope ensures a scope is registered on the unified Resource matching
// resourceURI. Idempotent: a scope with the same name is left untouched.
// Descriptions flow into the consent UI through the catalog read by 's
// ResourceRegistry.
func (h *TestHarness) RegisterScope(resourceURI, name, description string) {
	h.T.Helper()
	ctx := context.Background()
	rows, err := h.resourceStore.List(ctx, output.ResourceFilter{})
	if err != nil {
		h.T.Fatalf("list resources: %v", err)
	}
	for _, res := range rows {
		if res.URI != resourceURI {
			continue
		}
		for _, sc := range res.Scopes {
			if sc.Name == name {
				return
			}
		}
		res.Scopes = append(res.Scopes, resource.Scope{Name: name, Description: description})
		if err := h.resourceStore.Update(ctx, res); err != nil {
			h.T.Fatalf("update resource scopes: %v", err)
		}
		return
	}
}

// AuthorizeRuntimeClient adds clientID to the Resource's
// policy.runtime.client_ids — the only place Authplane learns which
// client_ids may act AS a Resource. Introspection needs it so a resource
// server may ask about tokens minted for it.
func (h *TestHarness) AuthorizeRuntimeClient(resourceURI, clientID string) {
	h.T.Helper()
	ctx := context.Background()
	rows, err := h.resourceStore.List(ctx, output.ResourceFilter{})
	if err != nil {
		h.T.Fatalf("list resources: %v", err)
	}
	for _, res := range rows {
		if res.URI != resourceURI {
			continue
		}
		for _, existing := range res.Policy.Runtime.ClientIDs {
			if existing == clientID {
				return
			}
		}
		res.Policy.Runtime.ClientIDs = append(res.Policy.Runtime.ClientIDs, clientID)
		if err := h.resourceStore.Update(ctx, res); err != nil {
			h.T.Fatalf("authorize runtime client: %v", err)
		}
		return
	}
	h.T.Fatalf("authorize runtime client: no resource with uri %q", resourceURI)
}

// ResourceServerClient registers confidential credentials and authorizes them
// to act AS the Resource at resourceURI. This models the RFC 7662 caller: a
// resource server asking the AS about a token one of its clients presented,
// which is never the client that owns the token.
func (h *TestHarness) ResourceServerClient(resourceURI string) (clientID, clientSecret string) {
	h.T.Helper()
	clientID, clientSecret = h.RegisterConfidentialClient([]string{"authorization_code"}, "")
	h.AuthorizeRuntimeClient(resourceURI, clientID)
	return clientID, clientSecret
}

// IntrospectAsResourceServer introspects token as the resource server for
// resourceURI, registering and authorizing fresh credentials on the way.
//
// Use it for a single assertion. Calling it twice around a state change gives
// each side a *different* caller, so an "expected inactive" assertion would
// pass on a broken entitlement setup exactly as readily as on the state change
// it means to prove. Where a test asserts before and after, call
// ResourceServerClient once and IntrospectToken twice with that pair —
// user_disable_test.go and token_lifecycle_test.go do.
func (h *TestHarness) IntrospectAsResourceServer(token, resourceURI string) *IntrospectResponse {
	h.T.Helper()
	rsID, rsSecret := h.ResourceServerClient(resourceURI)
	return h.IntrospectToken(token, rsID, rsSecret)
}

// NewClient creates an http.Client with a cookie jar for browser simulation.
func (h *TestHarness) NewClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects — we want to inspect Location headers.
			return http.ErrUseLastResponse
		},
	}
}

// Login performs a POST /login and asserts it succeeded.
func (h *TestHarness) Login(client *http.Client, email, password, redirect string) {
	h.T.Helper()

	resp, err := h.LoginResponse(client, email, password, redirect)
	if err != nil {
		// Not re-labelled: LoginResponse names the request that failed, which
		// is the GET as often as the POST.
		h.T.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		h.T.Fatalf("POST /login: expected 303, got %d", resp.StatusCode)
	}
}

// LoginResponse performs a POST /login and hands back the raw response so the
// caller can inspect headers the redirect itself carries. The body is still
// open; callers close it.
//
// The POST error is returned rather than fatal because a malformed Location
// header fails the round trip in the client, not the server: net/http parses
// Location before consulting CheckRedirect, so an unparseable value surfaces
// as a transport error. A caller asserting on redirect targets needs to see
// that per-case instead of losing the whole test — h.T is the parent *testing.T,
// so a Fatalf here would abort every remaining subtest. Login wraps this for
// the common case where only success matters.
func (h *TestHarness) LoginResponse(client *http.Client, email, password, redirect string) (*http.Response, error) {
	h.T.Helper()

	// First GET /login to get any initial cookie + CSRF token.
	loginURL := h.Issuer + "/login"
	if redirect != "" {
		loginURL += "?redirect=" + url.QueryEscape(redirect)
	}
	getResp, err := client.Get(loginURL)
	if err != nil {
		// No URL here: client.Get returns a *url.Error that already prints it.
		return nil, fmt.Errorf("login page fetch: %w", err)
	}
	body, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()

	csrfToken := extractCSRFToken(string(body))

	// POST /login with credentials.
	form := url.Values{
		"email":      {email},
		"password":   {password},
		"csrf_token": {csrfToken},
		"redirect":   {redirect},
	}
	return client.PostForm(h.Issuer+"/login", form)
}

// Authorize starts the authorization flow and returns the session ID from the consent redirect.
// If the user is logged in and has prior consent, it returns the auth code directly.
func (h *TestHarness) Authorize(client *http.Client, params url.Values) AuthorizeResult {
	h.T.Helper()

	authURL := h.Issuer + "/oauth/authorize?" + params.Encode()
	resp, err := client.Get(authURL)
	if err != nil {
		h.T.Fatalf("GET /oauth/authorize: %v", err)
	}
	resp.Body.Close()

	loc := resp.Header.Get("Location")
	if loc == "" {
		h.T.Fatalf("GET /oauth/authorize: no Location header, status=%d", resp.StatusCode)
	}

	locURL, err := url.Parse(loc)
	if err != nil {
		h.T.Fatalf("parse Location %q: %v", loc, err)
	}

	// Login redirect?
	if strings.HasPrefix(loc, "/login") {
		return AuthorizeResult{NeedsLogin: true, Location: loc}
	}

	// Consent redirect?
	if strings.HasPrefix(loc, "/consent") {
		sessionID := locURL.Query().Get("session_id")
		return AuthorizeResult{NeedsConsent: true, SessionID: sessionID, Location: loc}
	}

	// Direct redirect with code (prior consent).
	code := locURL.Query().Get("code")
	state := locURL.Query().Get("state")
	if code != "" {
		return AuthorizeResult{Code: code, State: state, Location: loc}
	}

	// Error redirect.
	errCode := locURL.Query().Get("error")
	errDesc := locURL.Query().Get("error_description")
	if errCode != "" {
		return AuthorizeResult{Error: errCode, ErrorDescription: errDesc, Location: loc}
	}

	h.T.Fatalf("unexpected authorize redirect: %s", loc)
	return AuthorizeResult{}
}

// GrantConsent POSTs consent approval and returns the auth code from the redirect.
func (h *TestHarness) GrantConsent(client *http.Client, sessionID string, scopes []string, remember bool) string {
	h.T.Helper()

	// GET /consent to get CSRF token.
	consentURL := fmt.Sprintf("%s/consent?session_id=%s", h.Issuer, url.QueryEscape(sessionID))
	getResp, err := client.Get(consentURL)
	if err != nil {
		h.T.Fatalf("GET /consent: %v", err)
	}
	body, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK {
		h.T.Fatalf("GET /consent: expected 200, got %d, body: %s", getResp.StatusCode, string(body))
	}

	csrfToken := extractCSRFToken(string(body))

	// POST /consent with approval.
	form := url.Values{
		"session_id": {sessionID},
		"csrf_token": {csrfToken},
		"action":     {"allow"},
	}
	for _, s := range scopes {
		form.Add("scopes", s)
	}
	if remember {
		form.Set("remember", "on")
	}

	resp, err := client.PostForm(h.Issuer+"/consent", form)
	if err != nil {
		h.T.Fatalf("POST /consent: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		h.T.Fatalf("POST /consent: expected 303, got %d", resp.StatusCode)
	}

	loc := resp.Header.Get("Location")
	locURL, err := url.Parse(loc)
	if err != nil {
		h.T.Fatalf("parse consent redirect: %v", err)
	}

	code := locURL.Query().Get("code")
	if code == "" {
		h.T.Fatalf("no code in consent redirect: %s", loc)
	}
	return code
}

// PostConsentRaw POSTs the consent form with arbitrary scopes and returns
// the raw response so tests can assert on the status code and body. Unlike
// GrantConsent (which expects a 303 redirect) this helper does not validate
// the response shape — it is used by negative-path tests like the
// zero-approved-scope rejection. CSRF is handled internally.
func (h *TestHarness) PostConsentRaw(client *http.Client, sessionID string, scopes []string) *http.Response {
	h.T.Helper()

	consentURL := fmt.Sprintf("%s/consent?session_id=%s", h.Issuer, url.QueryEscape(sessionID))
	getResp, err := client.Get(consentURL)
	if err != nil {
		h.T.Fatalf("GET /consent: %v", err)
	}
	body, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		h.T.Fatalf("GET /consent: expected 200, got %d", getResp.StatusCode)
	}
	csrfToken := extractCSRFToken(string(body))

	form := url.Values{
		"session_id": {sessionID},
		"csrf_token": {csrfToken},
		"action":     {"allow"},
	}
	for _, s := range scopes {
		form.Add("scopes", s)
	}
	resp, err := client.PostForm(h.Issuer+"/consent", form)
	if err != nil {
		h.T.Fatalf("POST /consent: %v", err)
	}
	return resp
}

// DenyConsent POSTs consent denial.
func (h *TestHarness) DenyConsent(client *http.Client, sessionID string) {
	h.T.Helper()

	// GET /consent to get CSRF token.
	consentURL := fmt.Sprintf("%s/consent?session_id=%s", h.Issuer, url.QueryEscape(sessionID))
	getResp, err := client.Get(consentURL)
	if err != nil {
		h.T.Fatalf("GET /consent: %v", err)
	}
	body, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()

	csrfToken := extractCSRFToken(string(body))

	form := url.Values{
		"session_id": {sessionID},
		"csrf_token": {csrfToken},
		"action":     {"deny"},
	}

	resp, err := client.PostForm(h.Issuer+"/consent", form)
	if err != nil {
		h.T.Fatalf("POST /consent deny: %v", err)
	}
	resp.Body.Close()
}

// ExchangeCode exchanges an authorization code for tokens.
func (h *TestHarness) ExchangeCode(code, verifier, clientID, redirectURI string) *TokenResponse {
	h.T.Helper()

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	}

	resp, err := http.PostForm(h.Issuer+"/oauth/token", form)
	if err != nil {
		h.T.Fatalf("POST /oauth/token: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		h.T.Fatalf("POST /oauth/token: expected 200, got %d, body: %s", resp.StatusCode, string(body))
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		h.T.Fatalf("decode token response: %v", err)
	}
	return &tr
}

// ExchangeCodeExpectError exchanges a code and expects an error.
func (h *TestHarness) ExchangeCodeExpectError(code, verifier, clientID, redirectURI string) *OAuthError {
	h.T.Helper()

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	}

	resp, err := http.PostForm(h.Issuer+"/oauth/token", form)
	if err != nil {
		h.T.Fatalf("POST /oauth/token: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		h.T.Fatalf("POST /oauth/token: expected error, got 200")
	}

	var oe OAuthError
	if err := json.Unmarshal(body, &oe); err != nil {
		h.T.Fatalf("decode error response: %v", err)
	}
	oe.StatusCode = resp.StatusCode
	return &oe
}

// RefreshToken exchanges a refresh token for new tokens.
func (h *TestHarness) RefreshToken(refreshToken, clientID string) *TokenResponse {
	h.T.Helper()

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	}

	resp, err := http.PostForm(h.Issuer+"/oauth/token", form)
	if err != nil {
		h.T.Fatalf("POST /oauth/token refresh: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		h.T.Fatalf("POST /oauth/token refresh: expected 200, got %d, body: %s", resp.StatusCode, string(body))
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		h.T.Fatalf("decode token response: %v", err)
	}
	return &tr
}

// RefreshTokenExpectError tries to refresh and expects an error.
func (h *TestHarness) RefreshTokenExpectError(refreshToken, clientID string) *OAuthError {
	h.T.Helper()

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	}

	resp, err := http.PostForm(h.Issuer+"/oauth/token", form)
	if err != nil {
		h.T.Fatalf("POST /oauth/token refresh: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		h.T.Fatalf("POST /oauth/token refresh: expected error, got 200")
	}

	var oe OAuthError
	if err := json.Unmarshal(body, &oe); err != nil {
		h.T.Fatalf("decode error response: %v", err)
	}
	oe.StatusCode = resp.StatusCode
	return &oe
}

// RevokeToken calls the revocation endpoint.
// An optional clientSecret can be provided for confidential clients.
func (h *TestHarness) RevokeToken(token, clientID string, clientSecret ...string) int {
	h.T.Helper()

	form := url.Values{
		"token":     {token},
		"client_id": {clientID},
	}
	if len(clientSecret) > 0 && clientSecret[0] != "" {
		form.Set("client_secret", clientSecret[0])
	}

	resp, err := http.PostForm(h.Issuer+"/oauth/revoke", form)
	if err != nil {
		h.T.Fatalf("POST /oauth/revoke: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// IntrospectToken calls POST /oauth/introspect and returns the response.
// An optional clientSecret can be provided for confidential clients.
func (h *TestHarness) IntrospectToken(token, clientID string, clientSecret ...string) *IntrospectResponse {
	h.T.Helper()

	form := url.Values{
		"token":     {token},
		"client_id": {clientID},
	}
	if len(clientSecret) > 0 && clientSecret[0] != "" {
		form.Set("client_secret", clientSecret[0])
	}

	resp, err := http.PostForm(h.Issuer+"/oauth/introspect", form)
	if err != nil {
		h.T.Fatalf("POST /oauth/introspect: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		h.T.Fatalf("POST /oauth/introspect: expected 200, got %d, body: %s", resp.StatusCode, string(body))
	}

	var ir IntrospectResponse
	if err := json.Unmarshal(body, &ir); err != nil {
		h.T.Fatalf("decode introspect response: %v", err)
	}
	return &ir
}

// IntrospectTokenStatus introspects and returns the raw HTTP status alongside
// the decoded body, for tests asserting on client-authentication refusals
// rather than on token state.
func (h *TestHarness) IntrospectTokenStatus(token, clientID, clientSecret string) (*IntrospectResponse, int) {
	h.T.Helper()

	form := url.Values{"token": {token}, "client_id": {clientID}}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	resp, err := http.PostForm(h.Issuer+"/oauth/introspect", form)
	if err != nil {
		h.T.Fatalf("POST /oauth/introspect: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var ir IntrospectResponse
	_ = json.Unmarshal(body, &ir)
	return &ir, resp.StatusCode
}

// SuspendClient suspends a client via the admin service.
func (h *TestHarness) SuspendClient(clientID string) {
	h.T.Helper()
	if err := h.AdminSvc.SuspendClient(context.Background(), clientID); err != nil {
		h.T.Fatalf("suspend client %s: %v", clientID, err)
	}
}

// DisableUser disables a user via the admin service.
func (h *TestHarness) DisableUser(userID string) {
	h.T.Helper()
	if err := h.AdminSvc.DisableUser(context.Background(), userID); err != nil {
		h.T.Fatalf("disable user %s: %v", userID, err)
	}
}

// DeleteUser hard-deletes a user via the admin service. Pass force=true to
// also revoke any active token families before the delete (otherwise the
// service refuses with ErrUserHasActiveTokens). Used by to simulate
// a stale-session scenario where the cookie still validates by HMAC but
// the userID no longer resolves in the user store.
func (h *TestHarness) DeleteUser(userID string, force bool) {
	h.T.Helper()
	if err := h.AdminSvc.DeleteUser(context.Background(), userID, force); err != nil {
		h.T.Fatalf("delete user %s: %v", userID, err)
	}
}

// RefreshTokenWithScope exchanges a refresh token with a specific scope.
func (h *TestHarness) RefreshTokenWithScope(refreshToken, clientID, scope string) *TokenResponse {
	h.T.Helper()

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"scope":         {scope},
	}

	resp, err := http.PostForm(h.Issuer+"/oauth/token", form)
	if err != nil {
		h.T.Fatalf("POST /oauth/token refresh: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		h.T.Fatalf("POST /oauth/token refresh: expected 200, got %d, body: %s", resp.StatusCode, string(body))
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		h.T.Fatalf("decode token response: %v", err)
	}
	return &tr
}

// RefreshTokenWithScopeExpectError refreshes with a scope and expects error.
func (h *TestHarness) RefreshTokenWithScopeExpectError(refreshToken, clientID, scope string) *OAuthError {
	h.T.Helper()

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"scope":         {scope},
	}

	resp, err := http.PostForm(h.Issuer+"/oauth/token", form)
	if err != nil {
		h.T.Fatalf("POST /oauth/token refresh: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		h.T.Fatalf("POST /oauth/token refresh: expected error, got 200")
	}

	var oe OAuthError
	if err := json.Unmarshal(body, &oe); err != nil {
		h.T.Fatalf("decode error response: %v", err)
	}
	oe.StatusCode = resp.StatusCode
	return &oe
}

// RefreshTokenRaw refreshes a token and returns HTTP status and body without calling t.Fatal.
// Safe for use in goroutines.
func (h *TestHarness) RefreshTokenRaw(refreshToken, clientID string) (int, []byte) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	}
	resp, err := http.PostForm(h.Issuer+"/oauth/token", form)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// RegisterClient registers a client via DCR.
func (h *TestHarness) RegisterClient(req input.RegisterClientRequest) (*input.RegisterClientResponse, int) {
	h.T.Helper()

	body, _ := json.Marshal(req)
	resp, err := http.Post(h.Issuer+"/oauth/register", "application/json", strings.NewReader(string(body)))
	if err != nil {
		h.T.Fatalf("POST /oauth/register: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusCreated {
		var reg input.RegisterClientResponse
		if err := json.Unmarshal(respBody, &reg); err != nil {
			h.T.Fatalf("decode register response: %v", err)
		}
		return &reg, resp.StatusCode
	}

	return nil, resp.StatusCode
}

// AuthorizeResult contains the result of an authorization request.
type AuthorizeResult struct {
	Code             string
	State            string
	SessionID        string
	NeedsLogin       bool
	NeedsConsent     bool
	Error            string
	ErrorDescription string
	Location         string
}

// TokenResponse mirrors the OAuth token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// IntrospectResponse mirrors the RFC 7662 introspection response.
type IntrospectResponse struct {
	Active    bool                   `json:"active"`
	Scope     string                 `json:"scope,omitempty"`
	ClientID  string                 `json:"client_id,omitempty"`
	Sub       string                 `json:"sub,omitempty"`
	Aud       string                 `json:"aud,omitempty"`
	Iss       string                 `json:"iss,omitempty"`
	Exp       int64                  `json:"exp,omitempty"`
	Iat       int64                  `json:"iat,omitempty"`
	Jti       string                 `json:"jti,omitempty"`
	TokenType string                 `json:"token_type,omitempty"`
	Cnf       map[string]interface{} `json:"cnf,omitempty"`
}

// TokenExchangeResponse mirrors the RFC 8693 token exchange response.
type TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope"`
}

// OAuthError mirrors an OAuth error response.
type OAuthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	// ConsentURL is populated when error=consent_required.
	ConsentURL string `json:"consent_url,omitempty"`
	// Cause is the sub-discriminator on consent_required errors:
	// "consent_missing" (no row) or "scope_insufficient" (row present
	// but scope subset missing). Empty for non-consent errors and for
	// legacy callers that did not supply one.
	Cause      string `json:"cause,omitempty"`
	StatusCode int    `json:"-"`
}

// RegisterConfidentialClient registers a confidential client via DCR and returns client_id + client_secret.
func (h *TestHarness) RegisterConfidentialClient(grantTypes []string, scope string) (clientID, clientSecret string) {
	h.T.Helper()

	reg, status := h.RegisterClient(input.RegisterClientRequest{
		RedirectURIs:            []string{"http://localhost:9999/callback"},
		ClientName:              "e2e-cc-client",
		GrantTypes:              grantTypes,
		TokenEndpointAuthMethod: "client_secret_post",
	})
	if status != http.StatusCreated {
		h.T.Fatalf("register confidential client: expected 201, got %d", status)
	}

	if scope != "" {
		c, err := h.clientStore.GetByID(context.Background(), reg.ClientID)
		if err != nil {
			h.T.Fatalf("get client for scope update: %v", err)
		}
		c.Scope = scope
		if err := h.clientStore.Update(context.Background(), c); err != nil {
			h.T.Fatalf("update client scope: %v", err)
		}
	}

	return reg.ClientID, reg.ClientSecret
}

// RegisterAgentClient registers a confidential agent client via DCR and returns client_id + client_secret.
func (h *TestHarness) RegisterAgentClient(grantTypes []string, scope, description string) (clientID, clientSecret string) {
	h.T.Helper()

	reg, status := h.RegisterClient(input.RegisterClientRequest{
		RedirectURIs:            []string{"http://localhost:9999/callback"},
		ClientName:              "e2e-agent-client",
		GrantTypes:              grantTypes,
		TokenEndpointAuthMethod: "client_secret_post",
		Agent:                   true,
		AgentDescription:        description,
	})
	if status != http.StatusCreated {
		h.T.Fatalf("register agent client: expected 201, got %d", status)
	}

	if scope != "" {
		c, err := h.clientStore.GetByID(context.Background(), reg.ClientID)
		if err != nil {
			h.T.Fatalf("get client for scope update: %v", err)
		}
		c.Scope = scope
		if err := h.clientStore.Update(context.Background(), c); err != nil {
			h.T.Fatalf("update client scope: %v", err)
		}
	}

	return reg.ClientID, reg.ClientSecret
}

// CreatePublicClientWithID / CreateConfidentialClientWithID /
// CreateAgentClientWithID were removed. The slug==client_id convention
// they enabled (caller-chosen IDs that doubled as Resource slugs) was
// retired. tests now route through the public admin API
// (AdminCreatePublicClient / AdminCreateConfidentialClient /
// AdminCreateAgentClient in admin_helpers.go), which lets the AS
// auto-generate the client_id and binds it to the Resource via
// policy.runtime.client_ids.

// ClientCredentialsExchange performs a client_credentials token exchange via the token endpoint.
func (h *TestHarness) ClientCredentialsExchange(clientID, clientSecret, scope, resource string) *TokenResponse {
	h.T.Helper()

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	if resource != "" {
		form.Set("resource", resource)
	}

	resp, err := http.PostForm(h.Issuer+"/oauth/token", form)
	if err != nil {
		h.T.Fatalf("POST /oauth/token client_credentials: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		h.T.Fatalf("POST /oauth/token client_credentials: expected 200, got %d, body: %s", resp.StatusCode, string(body))
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		h.T.Fatalf("decode token response: %v", err)
	}
	return &tr
}

// ClientCredentialsExchangeExpectError performs a client_credentials exchange expecting an error.
func (h *TestHarness) ClientCredentialsExchangeExpectError(clientID, clientSecret, scope string) *OAuthError {
	h.T.Helper()

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	if scope != "" {
		form.Set("scope", scope)
	}

	resp, err := http.PostForm(h.Issuer+"/oauth/token", form)
	if err != nil {
		h.T.Fatalf("POST /oauth/token client_credentials: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		h.T.Fatalf("POST /oauth/token client_credentials: expected error, got 200")
	}

	var oe OAuthError
	if err := json.Unmarshal(body, &oe); err != nil {
		h.T.Fatalf("decode error response: %v", err)
	}
	oe.StatusCode = resp.StatusCode
	return &oe
}

// TokenExchange performs an RFC 8693 token exchange via the token endpoint.
func (h *TestHarness) TokenExchange(clientID, clientSecret, subjectToken, subjectTokenType, actorToken, actorTokenType, scope string) *TokenExchangeResponse {
	h.T.Helper()

	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {subjectToken},
		"subject_token_type": {subjectTokenType},
		"client_id":          {clientID},
		"client_secret":      {clientSecret},
	}
	if actorToken != "" {
		form.Set("actor_token", actorToken)
	}
	if actorTokenType != "" {
		form.Set("actor_token_type", actorTokenType)
	}
	if scope != "" {
		form.Set("scope", scope)
	}

	resp, err := http.PostForm(h.Issuer+"/oauth/token", form)
	if err != nil {
		h.T.Fatalf("POST /oauth/token token_exchange: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		h.T.Fatalf("POST /oauth/token token_exchange: expected 200, got %d, body: %s", resp.StatusCode, string(body))
	}

	var tr TokenExchangeResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		h.T.Fatalf("decode token exchange response: %v", err)
	}
	return &tr
}

// TokenExchangeExpectError performs a token exchange expecting an error.
func (h *TestHarness) TokenExchangeExpectError(clientID, clientSecret, subjectToken, subjectTokenType, actorToken, actorTokenType, scope string) *OAuthError {
	h.T.Helper()

	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {subjectToken},
		"subject_token_type": {subjectTokenType},
		"client_id":          {clientID},
		"client_secret":      {clientSecret},
	}
	if actorToken != "" {
		form.Set("actor_token", actorToken)
	}
	if actorTokenType != "" {
		form.Set("actor_token_type", actorTokenType)
	}
	if scope != "" {
		form.Set("scope", scope)
	}

	resp, err := http.PostForm(h.Issuer+"/oauth/token", form)
	if err != nil {
		h.T.Fatalf("POST /oauth/token token_exchange: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		h.T.Fatalf("POST /oauth/token token_exchange: expected error, got 200")
	}

	var oe OAuthError
	if err := json.Unmarshal(body, &oe); err != nil {
		h.T.Fatalf("decode error response: %v", err)
	}
	oe.StatusCode = resp.StatusCode
	return &oe
}

// TokenExchangeWithResource performs an RFC 8693 token exchange with a resource parameter.
func (h *TestHarness) TokenExchangeWithResource(clientID, clientSecret, subjectToken, subjectTokenType, scope, resource string) *TokenExchangeResponse {
	h.T.Helper()

	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {subjectToken},
		"subject_token_type": {subjectTokenType},
		"client_id":          {clientID},
		"client_secret":      {clientSecret},
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	if resource != "" {
		form.Set("resource", resource)
	}

	resp, err := http.PostForm(h.Issuer+"/oauth/token", form)
	if err != nil {
		h.T.Fatalf("POST /oauth/token token_exchange: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		h.T.Fatalf("POST /oauth/token token_exchange (resource=%s): expected 200, got %d, body: %s", resource, resp.StatusCode, string(body))
	}

	var tr TokenExchangeResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		h.T.Fatalf("decode token exchange response: %v", err)
	}
	return &tr
}

// TokenExchangeWithResourceExpectError performs a token exchange with resource expecting an error.
func (h *TestHarness) TokenExchangeWithResourceExpectError(clientID, clientSecret, subjectToken, subjectTokenType, scope, resource string) *OAuthError {
	h.T.Helper()

	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {subjectToken},
		"subject_token_type": {subjectTokenType},
		"client_id":          {clientID},
		"client_secret":      {clientSecret},
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	if resource != "" {
		form.Set("resource", resource)
	}

	resp, err := http.PostForm(h.Issuer+"/oauth/token", form)
	if err != nil {
		h.T.Fatalf("POST /oauth/token token_exchange: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		h.T.Fatalf("POST /oauth/token token_exchange (resource=%s): expected error, got 200", resource)
	}

	var oe OAuthError
	if err := json.Unmarshal(body, &oe); err != nil {
		h.T.Fatalf("decode error response: %v", err)
	}
	oe.StatusCode = resp.StatusCode
	return &oe
}

// deletion: SeedConnection / SeedConnectionResourceOnly /
// seedBrokerProviderAndResource / SeedAgentAttestation removed. Tests
// that need to set up a (BrokerProvider + Broker Resource + BrokerGrant)
// trio drive the public path: AdminCreateBrokerProvider +
// AdminCreateResource (broker kind) for the registry rows, then
// RunFlowConnect to persist the BrokerGrant via /connect/{provider}.
// Tests that need an agent-attestation Mint Resource + ConsentGrant
// drive AdminCreateResource (mint kind) + RunFlowC1Consent (which
// upserts the consent_grants row through /authorize + /consent).

// GetSessionCookie extracts the authserver_session cookie value from an http.Client's jar.
func (h *TestHarness) GetSessionCookie(client *http.Client) string {
	h.T.Helper()
	u, _ := url.Parse(h.Issuer)
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == "authserver_session" {
			return c.Value
		}
	}
	h.T.Fatal("no authserver_session cookie found — was Login called?")
	return ""
}

// cloneValues returns a deep copy of v so concurrent reads after the
// handler returns can't race the recorder.
func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vs := range v {
		dup := make([]string, len(vs))
		copy(dup, vs)
		out[k] = dup
	}
	return out
}

// newMockUpstreamProvider creates an httptest server that simulates a
// third-party OAuth provider. When recorder is non-nil, every authorize and
// token request is captured for later assertion (see TestHarness.AuthorizeRequests
// / .TokenRequests).
func newMockUpstreamProvider(t *testing.T, cfg ConnectorConfig, recorder *mockUpstreamRecorder) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	// Token endpoint — returns tokens shaped per the request grant_type:
	//
	//   grant_type=refresh_token  → echoes the refresh_token from the
	//     request as the access_token. This is the path the
	//     brokerproto/oauth adapter uses on every Vend, and it is what
	//     lets SeedConnection's "the AS hands back the seeded token"
	//     contract hold end-to-end (the seed value flows in as the
	//     credential's refresh_token and out as the vended access_token).
	//
	//   anything else (default: authorization_code) → returns the
	//     configured cfg.AccessToken (or a deterministic mock if unset),
	//     preserving the legacy connect-flow behavior.
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if recorder != nil {
			recorder.mu.Lock()
			recorder.tokenForm = append(recorder.tokenForm, cloneValues(r.PostForm))
			recorder.mu.Unlock()
		}
		grantType := r.FormValue("grant_type")
		var accessToken string
		switch grantType {
		case "refresh_token":
			accessToken = r.FormValue("refresh_token")
			if accessToken == "" {
				accessToken = cfg.AccessToken
			}
		default:
			accessToken = cfg.AccessToken
			if accessToken == "" {
				accessToken = "mock-access-" + cfg.Service + "-" + hex.EncodeToString([]byte(r.FormValue("code")))[:8]
			}
		}

		resp := map[string]interface{}{
			"access_token": accessToken,
			"token_type":   "bearer",
		}
		if cfg.RefreshToken != "" {
			resp["refresh_token"] = cfg.RefreshToken
		}
		if cfg.ExpiresIn > 0 {
			resp["expires_in"] = cfg.ExpiresIn
		}
		if len(cfg.Scopes) > 0 {
			resp["scope"] = strings.Join(cfg.Scopes, " ")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// Authorize endpoint — in a real flow this would render a consent page.
	// For tests it just redirects back with a code.
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		if recorder != nil {
			recorder.mu.Lock()
			recorder.authorizeQuery = append(recorder.authorizeQuery, cloneValues(r.URL.Query()))
			recorder.mu.Unlock()
		}
		state := r.URL.Query().Get("state")
		redirectURI := r.URL.Query().Get("redirect_uri")
		if redirectURI == "" {
			redirectURI = "http://localhost/callback"
		}
		http.Redirect(w, r, redirectURI+"?code=mock-auth-code&state="+url.QueryEscape(state), http.StatusFound)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// RegisterTrustedIDP registers a trusted IdP directly in the store.
// This bypasses HTTPS validation since E2E mock IdPs run on HTTP localhost.
func (h *TestHarness) RegisterTrustedIDP(req input.RegisterIDPRequest) string {
	h.T.Helper()
	if h.idpStore == nil {
		h.T.Fatal("XAA not enabled in harness config — set EnableXAA")
	}

	audience := req.Audience
	if audience == "" {
		audience = h.Issuer
	}
	jwksURI := req.JWKSUri
	if jwksURI == "" {
		jwksURI = req.Issuer + "/.well-known/jwks.json"
	}

	now := time.Now().UTC()
	entity := idp.TrustedIDP{
		ID:        crypto.GenerateRandomString(16),
		Name:      req.Name,
		Issuer:    req.Issuer,
		JWKSUri:   jwksURI,
		Audience:  audience,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := h.idpStore.Save(context.Background(), entity); err != nil {
		h.T.Fatalf("register trusted IdP: %v", err)
	}
	return entity.ID
}

// RegisterTrustedIDPSimple is a thin wrapper over RegisterTrustedIDP that
// takes primitive args so tests can avoid importing internal/ports/input
// (Gate 0). Defaults: audience = harness issuer, jwksURI = issuer +
// /.well-known/jwks.json when empty.
func (h *TestHarness) RegisterTrustedIDPSimple(name, issuer, jwksURI string) string {
	h.T.Helper()
	return h.RegisterTrustedIDP(input.RegisterIDPRequest{
		Name:    name,
		Issuer:  issuer,
		JWKSUri: jwksURI,
	})
}

// CreateXAAPolicySimple is a thin wrapper over CreateXAAPolicy with
// primitive args so tests can avoid importing internal/ports/input
// (Gate 0). Creates a permissive (no-rules) policy bound to the given
// IdP.
func (h *TestHarness) CreateXAAPolicySimple(name, idpID string) string {
	h.T.Helper()
	return h.CreateXAAPolicy(input.CreatePolicyRequest{
		Name:  name,
		IDPID: idpID,
	})
}

// CreateXAAPolicy creates an XAA policy via the policy service.
func (h *TestHarness) CreateXAAPolicy(req input.CreatePolicyRequest) string {
	h.T.Helper()
	if h.xaaPolicySvc == nil {
		h.T.Fatal("XAA not enabled in harness config — set EnableXAA")
	}
	resp, err := h.xaaPolicySvc.CreatePolicy(context.Background(), req)
	if err != nil {
		h.T.Fatalf("create XAA policy: %v", err)
	}
	return resp.ID
}

// CreateSubjectMapping creates a subject mapping via the subject mapping service.
func (h *TestHarness) CreateSubjectMapping(req input.CreateMappingRequest) string {
	h.T.Helper()
	if h.subjectMapSvc == nil {
		h.T.Fatal("XAA not enabled in harness config — set EnableXAA")
	}
	resp, err := h.subjectMapSvc.CreateMapping(context.Background(), req)
	if err != nil {
		h.T.Fatalf("create subject mapping: %v", err)
	}
	return resp.ID
}

// JWTBearerExchange performs a jwt-bearer token exchange via POST /oauth/token.
func (h *TestHarness) JWTBearerExchange(clientID, clientSecret, assertion, scope string) *TokenResponse {
	h.T.Helper()

	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
		"client_id":  {clientID},
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	if scope != "" {
		form.Set("scope", scope)
	}

	resp, err := http.PostForm(h.Issuer+"/oauth/token", form)
	if err != nil {
		h.T.Fatalf("POST /oauth/token jwt-bearer: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		h.T.Fatalf("POST /oauth/token jwt-bearer: status %d, body: %s", resp.StatusCode, body)
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		h.T.Fatalf("decode token response: %v", err)
	}
	return &tr
}

// JWTBearerExchangeWithResource performs a jwt-bearer exchange with a resource parameter.
func (h *TestHarness) JWTBearerExchangeWithResource(clientID, clientSecret, assertion, scope, resource string) *TokenResponse {
	h.T.Helper()

	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
		"client_id":  {clientID},
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	if resource != "" {
		form.Set("resource", resource)
	}

	resp, err := http.PostForm(h.Issuer+"/oauth/token", form)
	if err != nil {
		h.T.Fatalf("POST /oauth/token jwt-bearer: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		h.T.Fatalf("POST /oauth/token jwt-bearer: status %d, body: %s", resp.StatusCode, body)
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		h.T.Fatalf("decode token response: %v", err)
	}
	return &tr
}

// JWTBearerExchangeExpectError performs a jwt-bearer exchange expecting an error.
func (h *TestHarness) JWTBearerExchangeExpectError(clientID, clientSecret, assertion, scope string) *OAuthError {
	h.T.Helper()

	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
		"client_id":  {clientID},
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	if scope != "" {
		form.Set("scope", scope)
	}

	resp, err := http.PostForm(h.Issuer+"/oauth/token", form)
	if err != nil {
		h.T.Fatalf("POST /oauth/token jwt-bearer: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		h.T.Fatalf("POST /oauth/token jwt-bearer: expected error, got 200, body: %s", body)
	}

	var oe OAuthError
	if err := json.Unmarshal(body, &oe); err != nil {
		h.T.Fatalf("decode error response: %v", err)
	}
	oe.StatusCode = resp.StatusCode
	return &oe
}

// csrfRe extracts CSRF token from HTML forms.
var csrfRe = regexp.MustCompile(`name="csrf_token"\s+value="([^"]+)"`)

func extractCSRFToken(html string) string {
	matches := csrfRe.FindStringSubmatch(html)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// MockUpstreamURL returns the base URL for the mock upstream that
// HarnessConfig.Connectors[].Service==slug registered. Empty string if
// no such mock is wired.  added the getter so admin-driven
// scenarios can POST a BrokerProvider whose config_data points at the
// in-process mock without re-routing through SeedConnection's
// auto-create.
func (h *TestHarness) MockUpstreamURL(slug string) string {
	return h.mockUpstreamURLs[slug]
}

// deletion: IssuanceStore(), ConsentGrantStore(),
// BrokerProviderStore(), ResourceStore() public accessors deleted.
// Tests must drive state through the public admin/HTTP API + Admin*
// helpers (e2e/admin_helpers.go) + RunFlow* drivers (this file). The
// underlying private fields are retained for the harness's own setup
// + the RegisterScope helper; callers cannot reach them. .

// AdminRequest issues an authenticated admin-API request against
// h.AdminAPI. body may be nil (no body), a []byte (raw payload), or any
// JSON-serialisable value (encoded with encoding/json). The Authorization
// header is set automatically; t.Fatal is called on transport errors.
// Caller is responsible for closing the response body.
//
// Use AdminPath for paths whose query string contains characters that
// must round-trip through net/url; AdminRequest accepts a fully-formed
// path-with-query.
func (h *TestHarness) AdminRequest(method, path string, body any) *http.Response {
	h.T.Helper()
	if h.AdminAPI == nil {
		h.T.Fatal("AdminAPI not enabled — set HarnessConfig.EnableAdminAPI=true")
	}

	var bodyReader io.Reader
	if body != nil {
		switch b := body.(type) {
		case []byte:
			bodyReader = strings.NewReader(string(b))
		default:
			data, err := json.Marshal(body)
			if err != nil {
				h.T.Fatalf("marshal admin request body: %v", err)
			}
			bodyReader = strings.NewReader(string(data))
		}
	}

	req, err := http.NewRequest(method, h.AdminAPI.URL+path, bodyReader)
	if err != nil {
		h.T.Fatalf("build admin request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+h.AdminAPIKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.T.Fatalf("do admin request: %v", err)
	}
	return resp
}

// deletion: SeedConsentGrant + SeedBrokerGrant deleted. The
// consent grant row is created by RunFlowC1Consent (driving /authorize
// + /consent over HTTP); the broker grant row is created by
// RunFlowConnect (driving the /connect/{provider} dance). Both flows
// exercise the public surface an operator following the docs would —
// matching Gate 0's premise that a passing test must prove the wired-
// through path works, not just that direct DB writes happen.

// RunFlowC1Consent walks the per-MCP consent flow against the live AS
// and returns the auth code, the matching PKCE verifier, and the
// cookiejar-backed http.Client used for the dance:
//
//  1. POST /login with the user's credentials (uses Login).
//  2. GET /oauth/authorize?response_type=code&...&resource=<slug>&scope=<requested>
//     → 302 to /consent?session_id=…
//  3. GET /consent → render the per-MCP screen (extracts csrf_token).
//  4. POST /consent with action=allow and scopes=<approvedScopes>
//     (pass an empty slice to deny instead) → 302 to the agent's
//     redirect_uri with ?code=…&state=…
//
// The caller exchanges the returned code via ExchangeCode(code,
// verifier, agentClientID, redirectURI). On the deny path the returned
// code is empty; verifier is empty too.
//
// password is the second of three positional credentials so callers can
// keep the (email, password) pairing the rest of the harness uses.
func (h *TestHarness) RunFlowC1Consent(
	email, password, agentClientID, redirectURI, resourceSlug string,
	requestedScopes, approvedScopes []string,
) (code, verifier string, client *http.Client) {
	h.T.Helper()
	httpClient := h.NewClient()

	pkceVerifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(pkceVerifier)
	scope := strings.Join(requestedScopes, " ")
	state := "flow-c1-" + crypto.GenerateRandomString(8)

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {agentClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {scope},
		"resource":              {resourceSlug},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}

	// Step 1: authorize → expect login redirect, then log in.
	result := h.Authorize(httpClient, params)
	if result.NeedsLogin {
		loginRedirect := extractRedirectParamForFlowC1(result.Location)
		h.Login(httpClient, email, password, loginRedirect)
		result = h.Authorize(httpClient, params)
	}

	// Step 2: consent decision — allow with the approved scopes, or deny.
	if len(approvedScopes) == 0 {
		if !result.NeedsConsent {
			h.T.Fatalf("RunFlowC1Consent(deny): expected consent redirect, got: %+v", result)
		}
		h.DenyConsent(httpClient, result.SessionID)
		return "", "", httpClient
	}
	if !result.NeedsConsent {
		h.T.Fatalf("RunFlowC1Consent: expected consent redirect, got: %+v", result)
	}
	authCode := h.GrantConsent(httpClient, result.SessionID, approvedScopes, false)
	if authCode == "" {
		h.T.Fatal("RunFlowC1Consent: no code returned from GrantConsent")
	}
	return authCode, pkceVerifier, httpClient
}

// extractRedirectParamForFlowC1 mirrors extractRedirectParam in
// e2e/scenarios/consent_test.go; duplicated here because the helper
// lives in the scenarios package and the harness can't import test
// files.
func extractRedirectParamForFlowC1(location string) string {
	u, err := url.Parse(location)
	if err != nil {
		return ""
	}
	return u.Query().Get("redirect")
}

// RunFlowConnect drives the full /connect/{providerSlug} dance against
// the harness's in-process mock upstream and persists a BrokerGrant for
// the (user, provider) tuple via the public surface. Steps:
//
//  1. POST /login with the user's credentials (cookie jar follows).
//  2. GET /connect/{providerSlug}?return_url=<AS-self> → 302 to the
//     mock upstream's /authorize endpoint.
//  3. GET that upstream URL — the harness's mock upstream auto-redirects
//     to /connect/{providerSlug}/callback with code + state.
//  4. GET the callback URL → 302 to return_url; the AS's CompleteConnect
//     handler runs the brokerproto/oauth adapter, which exchanges the
//     code for an upstream credential, encrypts it, and persists a
//     BrokerGrant row.
//
// On success the broker_grants row exists (verifiable via
// GET /connections or the admin grant endpoints). The helper returns
// no value and fails the test on any non-302 response in the dance.
//
// Preconditions:
//   - The user (email/password) was already created via h.CreateUser.
//   - The broker provider + Broker resource exist (via
//     h.AdminCreateBrokerProvider + h.AdminCreateResource), with
//     config_data pointing at h.MockUpstreamURL(providerSlug). See
//     e2e/scenarios/connect_flow_test.go for the canonical setup.
//   - The mock upstream is configured (HarnessConfig.Connectors)
//     with the access_token + refresh_token the test will use.
//
// Use this in place of h.SeedConnection(...) when migrating tests off
// the Gate-0 shortcut. RunFlowConnect drives the same code path
// an operator following the docs would; SeedConnection bypasses it.
//
// Companion to RunFlowC1Consent (which produces a consent_grants row
// via /authorize + /consent). Together they cover the two grant tables
// the harness used to populate via direct store writes.
func (h *TestHarness) RunFlowConnect(email, password, providerSlug string) {
	h.T.Helper()
	httpClient := h.NewClient()
	h.Login(httpClient, email, password, "")

	// AS-self bypass per : a return_url pointing at the AS
	// itself does not require the per-resource policy.connect.allowed_return_urls
	// allowlist. Lets the helper work without the test having to wire
	// AdminAddAllowedReturnURL.
	returnURL := h.Issuer + "/connections"
	startURL := h.Issuer + "/connect/" + providerSlug + "?return_url=" + url.QueryEscape(returnURL)

	startResp, err := httpClient.Get(startURL)
	if err != nil {
		h.T.Fatalf("RunFlowConnect(%s): GET /connect: %v", providerSlug, err)
	}
	defer startResp.Body.Close()
	if startResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(startResp.Body)
		h.T.Fatalf("RunFlowConnect(%s): StartConnect status = %d, want 302; body=%s",
			providerSlug, startResp.StatusCode, body)
	}
	upstreamLoc := startResp.Header.Get("Location")
	if upstreamLoc == "" {
		h.T.Fatalf("RunFlowConnect(%s): empty Location on /connect response", providerSlug)
	}

	upstreamResp, err := httpClient.Get(upstreamLoc)
	if err != nil {
		h.T.Fatalf("RunFlowConnect(%s): GET upstream %s: %v", providerSlug, upstreamLoc, err)
	}
	defer upstreamResp.Body.Close()
	if upstreamResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(upstreamResp.Body)
		h.T.Fatalf("RunFlowConnect(%s): upstream authorize status = %d, want 302; body=%s",
			providerSlug, upstreamResp.StatusCode, body)
	}
	callbackLoc := upstreamResp.Header.Get("Location")
	if callbackLoc == "" {
		h.T.Fatalf("RunFlowConnect(%s): empty Location on upstream response", providerSlug)
	}

	callbackResp, err := httpClient.Get(callbackLoc)
	if err != nil {
		h.T.Fatalf("RunFlowConnect(%s): GET callback %s: %v", providerSlug, callbackLoc, err)
	}
	defer callbackResp.Body.Close()
	if callbackResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(callbackResp.Body)
		h.T.Fatalf("RunFlowConnect(%s): callback status = %d, want 302; body=%s",
			providerSlug, callbackResp.StatusCode, body)
	}
}
