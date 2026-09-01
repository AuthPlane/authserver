package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spf13/cobra"

	apiadmin "github.com/authplane/authserver/api/admin"
	apipublic "github.com/authplane/authserver/api/public"
	"github.com/authplane/authserver/api/shared"
	brokerprotoapikey "github.com/authplane/authserver/internal/adapters/brokerproto/apikey"
	brokerprotooauth "github.com/authplane/authserver/internal/adapters/brokerproto/oauth"
	brokerprotoserviceaccount "github.com/authplane/authserver/internal/adapters/brokerproto/serviceaccount"
	"github.com/authplane/authserver/internal/adapters/cache"
	"github.com/authplane/authserver/internal/adapters/cimd"
	"github.com/authplane/authserver/internal/adapters/encryption"
	"github.com/authplane/authserver/internal/adapters/idpjwks"
	adapteroidc "github.com/authplane/authserver/internal/adapters/oidc"
	adaptersigning "github.com/authplane/authserver/internal/adapters/signing"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/adapters/storage"
	"github.com/authplane/authserver/internal/brokerproto"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/internal/ssrf"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the server",
	Long:  "Start the Authplane MCP Authorization Server.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runServe()
	},
}

func runServe() error {
	startTime := time.Now()

	// 1. Load configuration
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// 2. Setup observability
	obs, obsShutdown, err := observability.New(context.Background(), cfg.Observability)
	if err != nil {
		return fmt.Errorf("setup observability: %w", err)
	}
	defer func() { _ = obsShutdown(context.Background()) }()

	obs.Logger.Info("starting authserver",
		"version", version,
		"issuer", cfg.Server.Issuer,
		"address", cfg.Server.Address,
	)

	// 2a. Startup validation: warn if CORS is disabled.
	// The AS always serves browser-facing OAuth endpoints (/oauth/authorize,
	// /oauth/token, /oauth/introspect, /oauth/revoke). When AllowedOrigins is
	// empty, browser-based MCP clients (MCP Inspector, Claude Desktop, etc.)
	// silently fail on CORS preflight. Server-to-server-only deployments may
	// intentionally leave this empty, so this is a one-line warning, not a
	// fail-on-boot.
	warnIfCORSDisabled(obs.Logger, cfg.Server.AllowedOrigins)

	// 2a'. Feature self-check. Validate every required-config
	// combination before any service is constructed. Misconfigured features
	// (partial config, unknown driver values, broker resources missing
	// allowed_return_urls, …) fail boot here with a structured fatal log;
	// "explicitly disabled" features keep the AS booting but their runtime
	// endpoints will return a typed feature_disabled error pointing at the
	// config key.
	checks := config.SelfCheck(*cfg)
	if bad := config.MisconfiguredChecks(checks); len(bad) > 0 {
		obs.Logger.Error(config.FormatMisconfiguredReport(bad))
		return fmt.Errorf("authserver boot aborted: %d feature(s) misconfigured", len(bad))
	}
	obs.Logger.Info(config.FormatReport(checks))

	// 2b. Setup data encryptor (if configured)
	var dataEncryptor output.DataEncryptor
	if cfg.DataEncryption.Driver != "" {
		var encErr error
		dataEncryptor, encErr = encryption.Open(context.Background(), cfg.DataEncryption, obs)
		if encErr != nil {
			return fmt.Errorf("setup data encryptor: %w", encErr)
		}
		if c, ok := dataEncryptor.(io.Closer); ok {
			defer func() { _ = c.Close() }()
		}
		obs.Logger.Info("data encryptor initialized", "driver", dataEncryptor.DriverName())
	}

	// Config-secret seam: a composite backend implements both the write port
	// (SecretEncoder) and the read port (SecretResolver). With a data encryptor
	// configured, inline secrets encrypt into the enc_secret_* columns; otherwise
	// the seam runs env-only (the *_ref path), identical to before.
	var fieldEnc output.FieldEncryptor
	if dataEncryptor != nil {
		fieldEnc = static.NewDataEncryptorFieldEncryptor(dataEncryptor)
	}
	// brokerConfigSecrets is the strict (encrypt-or-ref) backend: a raw value with
	// no encryptor is rejected, and an encrypted column read with no decryptor fails
	// closed, so broker secrets are never stored as plaintext. The inline-allowed
	// decision is a property of the wired backend, not of caller input, so it cannot
	// be flipped per call. The inline-tolerant OIDC backend is wired separately in
	// the OIDC block below (it needs no encryptor — the OSS inline-plaintext path).
	brokerConfigSecrets := static.NewConfigSecretBackend(fieldEnc)

	// Boot probe: verify that every secret configured via a *_ref env var has
	// the named var set. Missing vars are fatal here — identical fail-fast UX to
	// the former eager os.Getenv in validate.go. Column-only secrets are skipped.
	if probeErr := probeSecretRefs(cfg); probeErr != nil {
		return fmt.Errorf("secret ref probe failed — set the missing env var(s) before starting: %w", probeErr)
	}

	// Deprecated config keys still work but are translated at load time; warn so
	// the operator migrates before the shim is removed in a future release.
	for _, migration := range cfg.DeprecatedKeysUsed() {
		obs.Logger.Warn("deprecated config key in use — update your configuration", "migration", migration)
	}

	// Client-secret hashing: HMAC-SHA256 when a pepper is configured, otherwise
	// bcrypt. Set once before any client authentication happens.
	crypto.SetClientSecretPepper(cfg.ClientSecretPepper)

	// 3. Setup storage (dispatches on cfg.Storage.Driver)
	ds, err := storage.Open(context.Background(), cfg.Storage, obs)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = ds.Close() }()

	if migrateErr := ds.Migrate(context.Background()); migrateErr != nil {
		return fmt.Errorf("migrate database: %w", migrateErr)
	}

	// front the user store with a small TTL cache. Transparent —
	// callers see output.UserStore. The hot path is SessionMiddleware's
	// GetByID lookup on every authenticated request. The
	// cache invalidates on Update/Delete so admin-driven changes propagate
	// inside this process without waiting for the TTL.
	//
	// The cache is always on (WithUserCache requires a non-nil cache); the
	// fixed 60s/1024 bound is intentional. A zero TTL here would expire every
	// entry immediately (a DB query per request), so keep it positive.
	ds = storage.WithUserCache(ds, cache.NewMemoryTTLBounded[*storage.Entry](60*time.Second, 1024))

	// 4. Setup key store via factory (no driver-specific logic here)
	keyResult, err := adaptersigning.Open(context.Background(), cfg, ds, dataEncryptor, obs)
	if err != nil {
		return fmt.Errorf("create key store: %w", err)
	}
	if keyResult.Closer != nil {
		defer func() { _ = keyResult.Closer.Close() }()
	}

	jwksSvc := services.NewJWKSService(keyResult.Store, cache.NewMemory[*jose.JSONWebKeySet](), cfg.Signing.Algorithm, obs.WithComponent("jwks"))

	// 5. Setup audit service
	auditSvc := services.NewAuditService(ds.Audit(), obs.WithComponent("audit"))

	// 6. Setup DCR mode (shared between DCR and CIMD services)
	dcrModeProvider := static.NewDCRModeProvider(cfg.DCR.Mode, cfg.DCR.ApprovedRedirects)

	// compute the runtime-enabled grant set once and feed it to
	// every client-registration seam (CIMD, DCR, admin) so a client whose
	// grant /oauth/token can't serve never lands as status=active.
	enabledGrants := config.EnabledGrantTypes(cfg)
	// One provider shared by every client-registration seam (CIMD, DCR, admin),
	// resolved per request inside each service.
	grantsProvider := static.NewEnabledGrantsProvider(enabledGrants)

	// CIMD config provider — shared by the CIMD service and the discovery
	// document (client_id_metadata_document_supported). Built unconditionally so
	// discovery can resolve CIMD.Enabled even when the CIMD service is off.
	cimdConfigProvider := static.NewCIMDConfigProvider(output.CIMDConfig{
		Enabled:      cfg.CIMD.Enabled,
		RequireHTTPS: cfg.CIMD.RequireHTTPS,
		CacheTTL:     cfg.CIMD.CacheTTL,
		FetchTimeout: cfg.CIMD.FetchTimeout,
	})

	// 6a. Setup CIMD service (if enabled)
	// CIMD receives DCR mode to enforce admin_only/approved_redirects.
	var cimdSvc *services.CIMDService
	if cfg.CIMD.Enabled {
		// The fetcher holds no policy knobs; the CIMDConfigProvider is the single
		// source of truth for RequireHTTPS/CacheTTL/FetchTimeout (and Enabled),
		// resolved per request inside the service.
		cimdFetcher := cimd.New(obs.WithComponent("cimd"))
		cimdSvc = services.NewCIMDService(
			ds.Client(), cimdFetcher, dcrModeProvider,
			cimdConfigProvider,
			obs.WithComponent("cimd-svc"),
			services.WithCIMDEnabledGrants(grantsProvider),
		)
		obs.Logger.Info("CIMD support enabled", "dcr_mode", cfg.DCR.Mode)
	}

	// 6b. Setup DCR service.
	dcrSvc := services.NewDCRService(
		ds.Client(), dcrModeProvider, obs.WithComponent("dcr"), auditSvc,
		services.WithDCREnabledGrants(grantsProvider),
	)

	// 7. Setup user auth service
	authSvc := services.NewUserAuthService(ds.User(), obs.WithComponent("auth"), auditSvc)

	// 7b. Setup OIDC federation (if enabled)
	// OIDC config provider — built unconditionally so the admin system report can
	// resolve OIDC enablement per request; the adapter/facade/route mounting below
	// stay gated on cfg.OIDC.Enabled.
	oidcConfig := static.NewOIDCConfigProvider(output.OIDCConfig{
		Enabled:            cfg.OIDC.Enabled,
		Issuer:             cfg.OIDC.Issuer,
		ClientID:           cfg.OIDC.ClientID,
		RedirectURI:        cfg.OIDC.RedirectURI,
		Scopes:             cfg.OIDC.Scopes,
		IncludeGroupsScope: cfg.OIDC.IncludeGroupsScope,
		ConnectorID:        cfg.OIDC.ConnectorID,
		ClientSecret:       []byte(cfg.OIDC.ClientSecret),
		ClientSecretRef:    cfg.OIDC.ClientSecretRef,
	})

	var oidcFacade *services.OIDCFacade
	if cfg.OIDC.Enabled {
		// The OIDC client secret stays in its config form: whichever of the inline
		// client_secret or the *_ref env-var name is set flows straight into the
		// DTO, and the resolver resolves it JIT at use time. The two are mutually
		// exclusive — config validation rejects setting both — so exactly one is
		// populated and no precedence applies here. The inline-tolerant
		// oidcConfigSecrets backend carries the inline value as plaintext at rest
		// (the default — no encryptor); a substitute backend swaps in an
		// encrypted store.
		oidcConfigSecrets := static.NewConfigSecretBackendInline(cfg.LegacyOIDCSecretRef())
		oidcProvider := adapteroidc.New(oidcConfig, oidcConfigSecrets, obs.WithComponent("oidc"))
		// Validate the upstream OIDC configuration at startup (discovery check)
		// so a misconfigured issuer fails fast here rather than as a 500 on the
		// first login. It also warms the discovery cache.
		if validateErr := oidcProvider.Validate(context.Background()); validateErr != nil {
			return fmt.Errorf("setup OIDC provider: %w", validateErr)
		}
		oidcFacade = services.NewOIDCFacade(oidcProvider, ds.User(), obs.WithComponent("oidc-facade"), auditSvc)
		obs.Logger.Info("OIDC federation enabled", "issuer", cfg.OIDC.Issuer, "display_name", cfg.OIDC.DisplayName)
	}

	// 7c. Seed config-defined resources + broker providers into DB.
	// Seed-on-startup is a convenience for first-boot bootstrap; after that,
	// manage these via the Admin API or CLI.  unifies the YAML shape
	// behind `resources:` + `broker_providers:`; the loops below mirror the
	// admin API contracts so YAML and admin-driven state agree.
	//
	// Idempotency is skip-on-existing (NOT upsert): if a row with the
	// matching slug already exists, the YAML entry is ignored. This is a
	// behavior change from the legacy `UpsertByURI` semantics — see the
	// PR description and CHANGELOG migration table for rationale.
	seedResourceAdminSvc := services.NewResourceAdminService(
		ds.Resource(), ds.BrokerProvider(), ds.Client(),
		obs.WithComponent("resource-admin-seed"), auditSvc,
	)
	seedBrokerProviderAdminSvc := services.NewBrokerProviderAdminService(
		ds.BrokerProvider(),
		obs.WithComponent("broker-provider-admin-seed"), auditSvc,
		brokerConfigSecrets,
	)

	// Order matters: providers first so resource broker_provider_slug
	// references can resolve via the slug→id index built afterward.
	for _, bp := range cfg.BrokerProviders {
		existing, lookupErr := seedBrokerProviderAdminSvc.GetBySlug(context.Background(), bp.Slug)
		if lookupErr != nil && !errors.Is(lookupErr, domain.ErrResourceNotFound) {
			return fmt.Errorf("seed broker_providers[%q]: lookup: %w", bp.Slug, lookupErr)
		}
		if existing != nil {
			// Idempotent reboot — keep the existing row's id; do not overwrite
			// operator-edited fields. Operators changing config_data via YAML
			// must DELETE then re-add via the admin API (documented).
			continue
		}
		raw, marshalErr := json.Marshal(bp.ConfigData)
		if marshalErr != nil {
			return fmt.Errorf("seed broker_providers[%q]: marshal config_data: %w", bp.Slug, marshalErr)
		}
		if createErr := seedBrokerProviderAdminSvc.Create(context.Background(), &resource.BrokerProvider{
			Slug:        bp.Slug,
			DisplayName: bp.DisplayName,
			Protocol:    resource.Protocol(bp.Protocol),
			ConfigData:  raw,
		}); createErr != nil {
			return fmt.Errorf("seed broker_providers[%q]: %w", bp.Slug, createErr)
		}
	}

	// Build the slug→id index AFTER the create loop runs so newly-seeded
	// providers are visible to the resource loop below.
	bpSlugToID, err := buildBrokerProviderSlugIndex(context.Background(), seedBrokerProviderAdminSvc)
	if err != nil {
		return fmt.Errorf("index broker_providers: %w", err)
	}

	for _, r := range cfg.Resources {
		existing, lookupErr := seedResourceAdminSvc.GetBySlug(context.Background(), r.Slug)
		if lookupErr != nil && !errors.Is(lookupErr, domain.ErrResourceNotFound) {
			return fmt.Errorf("seed resources[%q]: lookup: %w", r.Slug, lookupErr)
		}
		if existing != nil {
			continue
		}
		dom, convErr := resourceConfigUnifiedToDomain(r, bpSlugToID)
		if convErr != nil {
			return fmt.Errorf("seed resources[%q]: %w", r.Slug, convErr)
		}
		if createErr := seedResourceAdminSvc.Create(context.Background(), dom); createErr != nil {
			return fmt.Errorf("seed resources[%q]: %w", r.Slug, createErr)
		}
	}

	// 8. Always-on registry + brokerproto adapter wiring. The
	// unified ResourceRegistry replaces the legacy CachedResourceProvider —
	// every grant-emitting service consumes it through the same
	// ResourceLister interface. The brokerproto.Registry holds the OAuth /
	// API-key / service-account adapters consulted by BrokerIssuer +
	// ConnectService. Both are constructed unconditionally because the
	// runtime requires registry-or-bust dispatch; the dependencies are
	// all available at this point in the wiring.
	resourceRegistry := services.NewResourceRegistry(
		ds.Resource(), ds.BrokerProvider(), obs.WithComponent("resource-registry"),
	)
	resourceLister := resourceRegistry

	bpRegistry := brokerproto.NewRegistry()
	// SSRF-safe client for outbound broker calls (token/revoke endpoints
	// against admin-configured upstreams). The transport resolves hostnames
	// at dial time and refuses connections to private/loopback/link-local
	// IPs — the adapter-level validateExternalURL is an IP-literal guard
	// that runs before any DNS, and the transport closes the
	// hostname-that-resolves-to-private-IP / DNS-rebinding gap. CheckRedirect
	// returns the last response without following — every redirect hop would
	// otherwise need its own SSRF validation, and token/revoke endpoints
	// have no legitimate reason to redirect.
	bpHTTPClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: ssrf.NewSafeTransport(),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if regErr := bpRegistry.Register(brokerprotooauth.New(bpHTTPClient, brokerConfigSecrets)); regErr != nil {
		return fmt.Errorf("register brokerproto/oauth adapter: %w", regErr)
	}
	if regErr := bpRegistry.Register(brokerprotoapikey.New(brokerConfigSecrets)); regErr != nil {
		return fmt.Errorf("register brokerproto/apikey adapter: %w", regErr)
	}
	if regErr := bpRegistry.Register(brokerprotoserviceaccount.New(bpHTTPClient, brokerConfigSecrets)); regErr != nil {
		return fmt.Errorf("register brokerproto/serviceaccount adapter: %w", regErr)
	}

	brokerIssuer := services.NewBrokerIssuer(
		ds.BrokerGrant(), dataEncryptor, ds.Issuance(),
		bpRegistry,
		obs.WithComponent("broker-issuer"), auditSvc,
	)

	// OAuth config provider — shared by the authorize service (RequireScope),
	// the introspection endpoint gate, and the discovery document
	// (introspection_endpoint). IntrospectionEnabled is true because OSS always
	// registers the introspection service (mirrors the prior deps.Introspect !=
	// nil discovery condition).
	oauthConfigProvider := static.NewOAuthConfigProvider(output.OAuthConfig{
		RequireScope:         cfg.OAuth.RequireScope,
		IntrospectionEnabled: true,
	})

	authzSvc := services.NewAuthorizeService(
		ds.Client(), ds.Session(), ds.ConsentGrant(),
		cimdSvc, resourceRegistry,
		oauthConfigProvider,
		obs.WithComponent("authorize"),
	)
	if !cfg.OAuth.RequireScope {
		obs.Logger.Warn(
			"oauth.require_scope=false: authorize requests without scope default to the resource's full registered scope set; production deployments should set AUTHPLANE_OAUTH_REQUIRE_SCOPE=true (see docs/guides/deploy/hardened-deployment.md)",
		)
	}
	if !cfg.Session.FailClosed {
		obs.Logger.Warn(
			"session.fail_closed=false explicitly overrides the secure default (true); transient user-store errors will keep sessions valid. Only override when availability requirements outweigh revocation freshness (see docs/guides/deploy/hardened-deployment.md)",
		)
	}

	// 9. Setup consent service
	consentSvc := services.NewConsentService(
		ds.ConsentGrant(), ds.Session(), ds.Client(), resourceRegistry,
		obs.WithComponent("consent"), auditSvc,
	)
	consentSvc.WithConsentTransactions(ds.Transaction())

	// 10. Setup token service. MintIssuer signs Mint access tokens
	// and writes the issuances audit row; TokenService delegates to it from
	// ExchangeCode and RefreshToken.  will also register MintIssuer
	// into internal/issuer.Registry alongside BrokerIssuer for the
	// TokenExchangeService dispatch path.
	// 10.5. issuerProvider is the indirection that lets the AS issuer URL
	// vary per request (e.g. behind a reverse-proxy mount that rewrites
	// the host header). The static adapter returns cfg.Server.Issuer for
	// every call, so behavior is byte-identical to the previous release.
	issuerProvider := static.NewIssuerProvider(cfg.Server.Issuer)

	tokenConfigProvider := static.NewTokenConfigProvider(output.TokenConfig{
		AccessTokenExpiry:  cfg.DCR.DefaultTokenExpiry,
		RefreshTokenExpiry: cfg.DCR.DefaultRefreshExpiry,
	})
	mintIssuer := services.NewMintIssuer(
		jwksSvc, ds.Issuance(), issuerProvider, obs.WithComponent("mint-issuer"),
	)
	tokenSvc := services.NewTokenService(
		ds.Session(), ds.Token(), ds.Client(), ds.User(),
		jwksSvc, mintIssuer, tokenConfigProvider,
		obs.WithComponent("token"), auditSvc,
		ds.Revocation(), resourceLister,
	)
	tokenSvc.WithTokenTransactions(ds.Transaction())
	// Wire the unified ResourceRegistry so the auth-code and refresh-token
	// grants persist their issuances audit row (the FK target resources.id
	// can only be resolved through the registry). Without this the admin
	// Issuances list stays empty for every Mint token issued via standard
	// OAuth grants —  introduced the audit row but  deferred
	// the TokenService wiring; this closes that gap.
	tokenSvc.WithResourceRegistry(resourceRegistry)

	// Fronting-link service. Constructed
	// once at top level so the runtime path (TokenExchangeService) and the
	// admin surface (ResourceAdminService + FrontingAdminDeps below) share
	// a single instance. The admin-block conditional reuses this variable.
	frontingAdminSvc := services.NewFrontingService(
		ds.FrontingLink(), ds.Resource(), ds.Transaction(),
		obs.WithComponent("fronting-admin"), auditSvc,
	)

	// 11. Setup revocation service
	revokeSvc := services.NewRevocationService(ds.Token(), ds.Client(), ds.MachineToken(), jwksSvc, issuerProvider, obs.WithComponent("revoke"), auditSvc, ds.Revocation())

	// 11b. Setup introspection service (RFC 7662)
	introspectSvc := services.NewIntrospectionService(
		jwksSvc, ds.Revocation(), ds.MachineToken(), ds.Client(), ds.User(),
		issuerProvider, obs.WithComponent("introspect"), auditSvc,
	)
	// Lets a resource server introspect a token minted for it. Without this
	// the ownership check admits only the token's issuing client.
	introspectSvc.WithResourceRegistry(resourceRegistry)

	// 11c. Setup client credentials service (if enabled)
	ccConfigProvider := static.NewClientCredentialsConfigProvider(output.ClientCredentialsConfig{
		Enabled:     cfg.ClientCredentials.Enabled,
		TokenExpiry: cfg.ClientCredentials.TokenExpiry,
	})
	var clientCredsSvc *services.ClientCredentialsService
	if cfg.ClientCredentials.Enabled {
		clientCredsSvc = services.NewClientCredentialsService(
			ds.Client(), ds.MachineToken(), jwksSvc,
			issuerProvider, ccConfigProvider,
			obs.WithComponent("client-credentials"), auditSvc,
			resourceLister,
		)
		// emit per-token issuance audit rows for the admin
		// /admin/issuances list. Mirrors token.go's WithResourceRegistry.
		clientCredsSvc.WithIssuanceAudit(ds.Issuance(), resourceRegistry)
		obs.Logger.Info("client_credentials grant enabled",
			"token_expiry", cfg.ClientCredentials.TokenExpiry.String(),
		)
	}

	// 11d. Setup token exchange service (if enabled).  makes the
	// registry + consent-grant store + Mint/Broker issuers mandatory
	// constructor parameters; the legacy setters are gone.
	txConfigProvider := static.NewTokenExchangeConfigProvider(output.TokenExchangeConfig{
		Enabled:           cfg.TokenExchange.Enabled,
		AllowSelfExchange: cfg.TokenExchange.AllowSelfExchange,
		MaxChainDepth:     cfg.TokenExchange.MaxChainDepth,
		TokenExpiry:       cfg.TokenExchange.TokenExpiry,
	})
	var tokenExchangeSvc *services.TokenExchangeService
	if cfg.TokenExchange.Enabled {
		tokenExchangeSvc = services.NewTokenExchangeService(
			ds.Client(), ds.MachineToken(), jwksSvc, jwksSvc,
			ds.Revocation(), issuerProvider,
			txConfigProvider,
			resourceRegistry, ds.ConsentGrant(), mintIssuer, brokerIssuer,
			obs.WithComponent("token-exchange"), auditSvc,
		)
		obs.Logger.Info("token exchange grant enabled",
			"max_chain_depth", cfg.TokenExchange.MaxChainDepth,
			"token_expiry", cfg.TokenExchange.TokenExpiry.String(),
			"allow_self_exchange", cfg.TokenExchange.AllowSelfExchange,
		)
	}

	// 11e. Enable agent identity claims (Authplane extension) on token services.
	agentIdentitySvc := services.NewAgentIdentityService(ds.Client(), obs.WithComponent("agent-identity"))
	if clientCredsSvc != nil {
		clientCredsSvc.WithAgentIdentity(agentIdentitySvc)
	}
	if tokenExchangeSvc != nil {
		tokenExchangeSvc.WithAgentIdentity(agentIdentitySvc)
		tokenExchangeSvc.WithResourceScopes(resourceLister)
	}
	if tokenExchangeSvc != nil {
		tokenExchangeSvc.WithFronting(frontingAdminSvc)
	}
	// (jwt-bearer agent identity is wired after service creation in 11i)

	// 11f. Wire JWKS agent listing via per-request AgentsConfigProvider.
	// The provider gates listing on every request; the client store is always
	// injected so it is available when the flag is enabled at runtime. The same
	// provider drives the discovery document's authplane_agent_identity_supported
	// (AgentIdentityEnabled=true preserves the previously hardcoded value).
	agentsConfigProvider := static.NewAgentsConfigProvider(output.AgentsConfig{
		EnableJWKSListing:    cfg.Agents.EnableJWKSListing,
		AgentIdentityEnabled: true,
	})
	jwksSvc.WithAgentsConfig(agentsConfigProvider)
	jwksSvc.WithAgentListing(ds.Client())
	if cfg.Agents.EnableJWKSListing {
		obs.Logger.Info("JWKS agent listing enabled")
	}

	// 11g. Enable DPoP proof-of-possession (RFC 9449) on token services.
	// Built unconditionally so the discovery document can resolve
	// dpop_signing_alg_values_supported from DPoP.Enabled; only wired into the
	// token services when DPoP is actually enabled.
	dpopProvider := static.NewDPoPConfigProvider(output.DPoPConfig{
		Enabled:       cfg.DPoP.Enabled,
		ProofLifetime: cfg.DPoP.ProofLifetime,
		RequireNonce:  cfg.DPoP.RequireNonce,
		NonceTTL:      cfg.DPoP.NonceTTL,
	})
	if cfg.DPoP.Enabled {
		tokenSvc.WithDPoP(ds.DPoPNonce(), dpopProvider)
		if clientCredsSvc != nil {
			clientCredsSvc.WithDPoP(ds.DPoPNonce(), dpopProvider)
		}
		if tokenExchangeSvc != nil {
			tokenExchangeSvc.WithDPoP(ds.DPoPNonce(), dpopProvider)
		}
		obs.Logger.Info("DPoP enabled",
			"proof_lifetime", cfg.DPoP.ProofLifetime.String(),
			"require_nonce", cfg.DPoP.RequireNonce,
		)
	}

	// 11h. Setup XAA (Enterprise-Managed Authorization) services.
	var xaaIDPSvc *services.XAAIDPService
	var xaaJWKSCache *idpjwks.Cache
	if cfg.XAA.Enabled {
		cacheCfg := idpjwks.CacheConfig{
			TTL: cfg.XAA.JWKSCacheTTL,
		}
		if cacheCfg.TTL == 0 {
			cacheCfg.TTL = 1 * time.Hour
		}

		xaaJWKSCache = idpjwks.New(
			ds.IDP(),
			cache.NewMemory[*idpjwks.Entry](),
			cacheCfg,
			obs.WithComponent("idp-jwks"),
		)
		xaaIDPSvc = services.NewXAAIDPService(
			ds.IDP(), xaaJWKSCache, idpjwks.DiscoverJWKSUri,
			issuerProvider, obs.WithComponent("xaa-idp"), auditSvc,
		)
		obs.Logger.Info("XAA (Enterprise-Managed Authorization) enabled")
	}

	// 11i. Setup JWT Bearer service (if XAA enabled).
	var jwtBearerSvc *services.JWTBearerService
	if cfg.XAA.Enabled && xaaJWKSCache != nil {
		tokenExpiry := cfg.XAA.TokenExpiry
		if tokenExpiry == 0 {
			tokenExpiry = 1 * time.Hour
		}
		maxAge := cfg.XAA.MaxAssertionAge
		if maxAge == 0 {
			maxAge = 5 * time.Minute
		}
		subjectMode := cfg.XAA.SubjectMode
		if subjectMode == "" {
			subjectMode = "auto_map"
		}
		jwtBearerSvc = services.NewJWTBearerService(
			ds.IDP(), xaaJWKSCache, ds.AssertionJTI(),
			ds.Client(), ds.MachineToken(), jwksSvc,
			issuerProvider,
			static.NewXAAConfigProvider(output.XAAConfig{
				Enabled:         cfg.XAA.Enabled,
				MaxAssertionAge: maxAge,
				SubjectMode:     subjectMode,
				JWKSCacheTTL:    cfg.XAA.JWKSCacheTTL,
				RequireResource: cfg.XAA.RequireResource,
				TokenExpiry:     tokenExpiry,
			}),
			obs.WithComponent("jwt-bearer"), auditSvc,
			resourceLister,
		)
		// emit per-token issuance audit rows for the admin
		// /admin/issuances list.
		jwtBearerSvc.WithIssuanceAudit(ds.Issuance(), resourceRegistry)
		// Enable DPoP on jwt-bearer if DPoP is configured. Gate on cfg.DPoP.Enabled
		// (not dpopProvider != nil): dpopProvider is now always non-nil because the
		// discovery document needs it to resolve DPoP.Enabled, so the old
		// nil-means-disabled idiom no longer holds — match the other token services.
		if cfg.DPoP.Enabled {
			jwtBearerSvc.WithDPoP(ds.DPoPNonce(), dpopProvider)
		}
		// Enable agent identity on jwt-bearer.
		jwtBearerSvc.WithAgentIdentity(agentIdentitySvc)

		obs.Logger.Info("jwt-bearer grant enabled",
			"token_expiry", tokenExpiry.String(),
			"max_assertion_age", maxAge.String(),
		)
	}

	// 11j. Setup XAA Policy + Subject Mapping services (if XAA enabled).
	var xaaPolicySvc *services.XAAPolicyService
	var subjectMappingSvc *services.SubjectMappingService
	if cfg.XAA.Enabled {
		xaaPolicySvc = services.NewXAAPolicyService(
			ds.XAAPolicy(), ds.IDP(),
			obs.WithComponent("xaa-policy"), auditSvc,
		)
		subjectMappingSvc = services.NewSubjectMappingService(
			ds.SubjectMapping(), ds.IDP(),
			obs.WithComponent("subject-mapping"),
		)

		// Wire policy + subject mapping into JWT Bearer service.
		if jwtBearerSvc != nil {
			jwtBearerSvc.WithPolicy(xaaPolicySvc, subjectMappingSvc)
			obs.Logger.Info("XAA policy engine enabled")
		}
	}

	// 12. Setup admin service
	adminSvc := services.NewAdminService(
		ds.Client(), ds.User(), ds.Token(), ds.Audit(),
		obs.WithComponent("admin"), auditSvc,
		services.WithMachineTokenStore(ds.MachineToken()),
		services.WithRevocationStore(ds.Revocation()),
		services.WithTransactionManager(ds.Transaction()),
		services.WithEnabledGrants(grantsProvider),
		// Wire the audit-feed lookback bound from cfg.Admin. An alternative
		// provider may resolve it per request.
		services.WithAuditQueryConfig(static.NewAuditQueryConfigProvider(output.AuditQueryConfig{
			DefaultLookback: cfg.Admin.AuditDefaultLookback,
			MaxLookback:     cfg.Admin.AuditMaxLookback,
		})),
	)

	// 12b. Setup ConnectService — the user-facing /connect/{provider} flow
	// over the unified BrokerProvider + BrokerGrant + ConnectPendingState
	// trio.  rewired this onto brokerproto.Registry; broker_providers
	// come from the unified store rather than from the deleted cfg.Connectors.
	var connectSvc *services.ConnectService
	if dataEncryptor != nil && cfg.Connect.StateSecret != "" {
		connectSvc = services.NewConnectService(
			resourceRegistry, ds.Resource(), ds.BrokerProvider(), ds.BrokerGrant(), ds.ConnectPendingState(),
			bpRegistry, dataEncryptor,
			static.NewConnectStateConfigProvider([]byte(cfg.Connect.StateSecret)),
			issuerProvider,
			static.NewConnectConfigProvider(output.ConnectConfig{
				AllowedReturnURLs: cfg.Connect.AllowedReturnURLs,
				RedirectBaseURL:   cfg.Connect.RedirectBaseURL,
			}),
			obs.WithComponent("connect"), auditSvc,
		)
		if cfg.Connect.RedirectBaseURL == "" {
			obs.Logger.Warn("connect.redirect_base_url is empty — falling back to issuer for upstream callback URLs")
		}
		obs.Logger.Info("upstream-connection support enabled")
	}

	if !cfg.OIDC.ShowLocalLogin && (!cfg.OIDC.Enabled || cfg.OIDC.DisplayName == "") {
		obs.Logger.Warn("oidc.show_local_login=false with no IdP button (oidc.enabled=false or oidc.display_name empty): " +
			"the login page offers no sign-in control; set oidc.display_name with oidc.enabled=true, " +
			"or recover with the authserver admin CLI, which works directly against the datastore, or the admin API if it is enabled")
	}

	// 13. Create HTTP server
	loginDisplay := static.NewLoginDisplayProvider(cfg.OIDC)
	urlBuilder := static.NewURLBuilder()

	// AS metadata discovery document assembler. Resolves every advertised
	// capability per request from the static providers above; api/ may not
	// import services/adapters, so it is built here and injected as a port.
	asMetadataSvc := services.NewASMetadataService(
		issuerProvider,
		grantsProvider,
		cimdConfigProvider,
		dpopProvider,
		oauthConfigProvider,
		agentsConfigProvider,
		resourceLister,
		obs.WithComponent("as-metadata"),
	)

	deps := apipublic.Deps{
		JWKS:          jwksSvc,
		ASMetadata:    asMetadataSvc,
		DCR:           dcrSvc,
		Auth:          authSvc,
		Authorize:     authzSvc,
		Consent:       consentSvc,
		Token:         tokenSvc,
		Revoke:        revokeSvc,
		Introspect:    introspectSvc,
		OAuthConfig:   oauthConfigProvider,
		Health:        ds,
		OIDC:          oidcFacade,
		LoginDisplay:  loginDisplay,
		URLs:          urlBuilder,
		SessionCookie: apipublic.SessionCookie{Name: cfg.Session.CookieName, Secure: cfg.Session.Secure},
		RateLimitCfg:  cfg.RateLimit,
		Audit:         auditSvc,
	}
	// Avoid typed-nil → interface assignment (Go nil interface gotcha).
	if clientCredsSvc != nil {
		deps.ClientCredentials = clientCredsSvc
	}
	if tokenExchangeSvc != nil {
		deps.TokenExchange = tokenExchangeSvc
	}
	if jwtBearerSvc != nil {
		deps.JWTBearer = jwtBearerSvc
	}
	if connectSvc != nil {
		deps.Connect = connectSvc
	}
	// IssuerProvider drives both consent_url flavors in OAuth
	// consent_required errors: the broker upstream re-connect URL
	// (/connect/<provider>, bound-D / bound-E) and the AS-side re-consent
	// URL (/authorize?resource=…, bound-B / bound-C token-exchange flows).
	// Reuses the same static issuer adapter the token/introspection/revoke
	// services use, so the consent URLs share the issuer host.
	//
	// The AS-side flavor is byte-identical to before (it already derived
	// from the issuer). The broker re-connect flavor previously used
	// cfg.Connect.RedirectBaseURL: collapsing it onto the issuer is a no-op
	// for every shipped config (redirect_base_url equals — or defaults to —
	// server.issuer), but changes the consent_url host for an operator who
	// sets the two differently. RedirectBaseURL still feeds the broker
	// callback redirect_uri separately (see ConnectService wiring above).
	deps.IssuerProvider = issuerProvider
	// CORS allowed-origins provider (required by NewServer). The OSS default
	// returns the boot cfg.Server.AllowedOrigins list on every call, so origin
	// policy is byte-identical to the pre-seam server; an alternative provider
	// may resolve the allowlist per request.
	deps.CORSConfigProvider = static.NewCORSConfigProvider(cfg.Server.AllowedOrigins)
	if cfg.DPoP.Enabled {
		deps.DPoPNonce = ds.DPoPNonce()
		deps.DPoPCfg = cfg.DPoP
	}
	// SessionMiddleware will look up userID in ds.User() to reject cookies
	// naming a user who has been deleted OR disabled — /authorize and /consent
	// have no user check of their own, so this is what makes a disable take
	// effect on the front channel. The user-store cache applied above
	// (storage.WithUserCache) keeps that lookup cheap.
	deps.Users = ds.User()

	// Resolve the effective session secret once, here, so the StateCodec and
	// the SessionSecretProvider below are derived from the same bytes. When the
	// operator left it unset (localhost-only path per cfg validation), fall back
	// to a random ephemeral secret (sessions will not survive a restart).
	sessionSecret := []byte(cfg.Session.Secret)
	if len(sessionSecret) == 0 {
		sessionSecret = make([]byte, 32)
		if _, err := rand.Read(sessionSecret); err != nil {
			panic("crypto/rand: " + err.Error())
		}
		obs.Logger.Warn("session.secret not configured - using random ephemeral secret (sessions will not survive restarts)")
	}

	// Construct the default OIDC state codec UNCONDITIONALLY. The OIDC
	// flow provider may be non-nil even when cfg.OIDC.Enabled is false
	// (typed-nil interface gotcha at the OIDC: assignment), and the
	// nil-guard in RegisterOIDCRoutes panics regardless of upstream
	// config. The codec key is derived from the session secret with
	// purpose "oidc-state" (matching the prior in-place derivation in
	// RegisterOIDCRoutes).
	stateConfig := static.NewStateCodecConfigProvider(shared.DeriveKey(sessionSecret, "oidc-state"))
	deps.StateCodec = static.NewStateCodec(stateConfig)

	// Wire the default OIDC state-cookie TTL provider from cfg.OAuth.StateMaxAge.
	// This governs both the state cookie's Max-Age attribute and the callback
	// freshness window; an alternative provider may resolve it per request.
	deps.OIDCStateConfigProvider = static.NewOIDCStateConfigProvider(output.OIDCStateConfig{
		MaxAge: cfg.OAuth.StateMaxAge,
	})

	// Wire the default session-cookie secret provider from the same resolved
	// secret. An alternative provider can be substituted here (per deployment).
	deps.SessionSecretProvider = static.NewSessionSecretProvider(sessionSecret)

	// Wire the default session-cookie policy provider from cfg.Session. The OSS
	// default returns the boot policy on every call (byte-identical to the
	// pre-seam server); an alternative provider may resolve policy per request.
	deps.SessionConfigProvider = static.NewSessionConfigProvider(output.SessionConfig{
		MaxAge:     cfg.Session.MaxAge,
		Secure:     cfg.Session.Secure,
		SameSite:   shared.ParseSameSite(cfg.Session.SameSite),
		FailClosed: cfg.Session.FailClosed,
	})

	srv := apipublic.NewServer(context.Background(), cfg.Server, deps, obs.WithComponent("http"))

	// 14. Start admin server (if enabled)
	var adminSrv *apiadmin.Server
	if cfg.Admin.Enabled {
		systemDeps := &apiadmin.SystemDeps{
			Version:          version,
			StartTime:        startTime,
			DBPing:           ds.Ping,
			StorageDriver:    cfg.Storage.Driver,
			KeyStoreDriver:   cfg.Signing.KeyStore,
			EncryptionDriver: cfg.DataEncryption.Driver,
			SigningAlgorithm: cfg.Signing.Algorithm,
			RateLimitEnabled: cfg.RateLimit.Enabled,
			Audit:            auditSvc,

			Issuer:            issuerProvider,
			DPoP:              dpopProvider,
			DCRMode:           dcrModeProvider,
			Agents:            agentsConfigProvider,
			ClientCredentials: ccConfigProvider,
			TokenExchange:     txConfigProvider,
			OIDC:              oidcConfig,
		}

		keysDeps := &apiadmin.KeysDeps{
			KeyAdmin: jwksSvc,
			Audit:    auditSvc,
		}

		// Load persisted DCR mode from runtime settings (if any).
		if persistedMode, err := ds.RuntimeSettings().Get(context.Background(), "dcr_mode"); err != nil {
			obs.Logger.Warn("failed to load persisted DCR mode", "error", err)
		} else if persistedMode != "" {
			// Defense in depth: the admin endpoint validates writes, but never
			// restore an unrecognized persisted value unchecked — an invalid mode
			// would skew enforcement (DCR rejects all, CIMD would otherwise open).
			switch persistedMode {
			case "open", "approved_redirects", "admin_only":
				if err := dcrSvc.SetMode(context.Background(), persistedMode); err != nil {
					obs.Logger.Error("failed to set persisted DCR mode", "error", err)
				} else {
					obs.Logger.Info("restored persisted DCR mode", "mode", persistedMode)
				}
			default:
				obs.Logger.Error("ignoring invalid persisted DCR mode", "mode", persistedMode)
			}
		}

		dcrDeps := &apiadmin.DCRDeps{
			DCR:      dcrSvc,
			Settings: ds.RuntimeSettings(),
			Audit:    auditSvc,
		}

		var xaaDeps *apiadmin.XAADeps
		if xaaIDPSvc != nil {
			xaaDeps = &apiadmin.XAADeps{
				IDP:            xaaIDPSvc,
				Policy:         xaaPolicySvc,
				SubjectMapping: subjectMappingSvc,
				Config:         static.NewXAAConfigProvider(output.XAAConfig{Enabled: cfg.XAA.Enabled}),
			}
		}

		// Fronting-link admin surface. The service itself is
		// constructed at top-level alongside other token services so the
		// runtime token-exchange path can consult the same instance; here
		// we only wire the HTTP admin deps. ResourceAdminService below
		// also consults it for edit-time validation + cascade-on-delete.
		frontingAdminDeps := &apiadmin.FrontingAdminDeps{Fronting: frontingAdminSvc}

		// Unified-resource + broker-provider admin services.
		// Always available — DB-backed. ResourceAdminService takes the
		// ClientStore for policy.exchange.allowed_client_ids validation; the
		// coupling is intentional and bounded.
		resourceAdminSvc := services.NewResourceAdminService(
			ds.Resource(), ds.BrokerProvider(), ds.Client(),
			obs.WithComponent("resource-admin"), auditSvc,
			services.WithFrontingValidator(frontingAdminSvc),
			services.WithResourceAdminTransactionManager(ds.Transaction()),
		)
		resourceAdminDeps := &apiadmin.ResourceAdminDeps{Resources: resourceAdminSvc}
		brokerProviderAdminSvc := services.NewBrokerProviderAdminService(
			ds.BrokerProvider(),
			obs.WithComponent("broker-provider-admin"), auditSvc,
			brokerConfigSecrets,
		)
		brokerProviderAdminDeps := &apiadmin.BrokerProviderAdminDeps{BrokerProviders: brokerProviderAdminSvc}

		// Grant + issuance admin services. Always available
		// — DB-backed. GrantAdminService takes the IssuanceStore as well
		// so RevokeConsent can cascade onto matching live Mint issuances
		// per the data model; IssuanceAdminService is straight-through
		// over the same store.
		grantAdminSvc := services.NewGrantAdminService(
			ds.ConsentGrant(), ds.BrokerGrant(), ds.Issuance(),
			obs.WithComponent("grant-admin"), auditSvc,
		)
		grantAdminDeps := &apiadmin.GrantAdminDeps{Grants: grantAdminSvc}
		issuanceAdminSvc := services.NewIssuanceAdminService(
			ds.Issuance(),
			obs.WithComponent("issuance-admin"), auditSvc,
		)
		issuanceAdminDeps := &apiadmin.IssuanceAdminDeps{Issuances: issuanceAdminSvc}

		var aerr error
		adminSrv, aerr = apiadmin.NewServer(context.Background(), cfg.Admin, adminSvc, obs.WithComponent("admin-http"), apiadmin.OptionalDeps{
			System:          systemDeps,
			Keys:            keysDeps,
			DCR:             dcrDeps,
			XAA:             xaaDeps,
			Resources:       resourceAdminDeps,
			BrokerProviders: brokerProviderAdminDeps,
			Grants:          grantAdminDeps,
			Issuances:       issuanceAdminDeps,
			Fronting:        frontingAdminDeps,
		})
		if aerr != nil {
			return fmt.Errorf("admin server: %w", aerr)
		}
	}

	// 15. Run with graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start LISTEN/NOTIFY listener if the signing driver supports it.
	if keyResult.RunNotify != nil {
		keyResult.RunNotify(ctx, jwksSvc.Reload)
		if err := jwksSvc.Reload(context.Background()); err != nil {
			obs.Logger.Warn("initial JWKS reload failed (will retry on first request)", "error", err)
		}
	}

	// SIGHUP handler for manual key reload.
	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				obs.Logger.Error("panic in SIGHUP handler", "panic", r)
			}
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case <-sighupCh:
				obs.Logger.Info("SIGHUP received, reloading signing keys")
				if err := jwksSvc.Reload(context.Background()); err != nil {
					obs.Logger.Error("SIGHUP key reload failed", "error", err)
				}
			}
		}
	}()

	errCh := make(chan error, 2)
	go func() {
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	if adminSrv != nil {
		go func() {
			if err := adminSrv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
	}

	select {
	case err := <-errCh:
		return fmt.Errorf("server: %w", err)
	case <-ctx.Done():
		obs.Logger.Info("shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownWait)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			obs.Logger.Error("http shutdown error", "error", err)
		}
		if adminSrv != nil {
			if err := adminSrv.Shutdown(shutCtx); err != nil {
				obs.Logger.Error("admin shutdown error", "error", err)
			}
		}
		obs.Logger.Info("stopped gracefully")
		return nil
	}
}

// buildBrokerProviderSlugIndex enumerates broker providers and returns a
// slug→id map used by the resource-seed loop to resolve broker_provider_slug
// references. Called after the broker_providers seed loop so newly-created
// rows are visible.
func buildBrokerProviderSlugIndex(ctx context.Context, svc input.BrokerProviderAdminPort) (map[string]string, error) {
	rows, err := svc.List(ctx)
	if err != nil {
		return nil, err
	}
	index := make(map[string]string, len(rows))
	for _, p := range rows {
		index[p.Slug] = p.ID
	}
	return index, nil
}

// resourceConfigUnifiedToDomain converts a YAML ResourceConfigUnified entry
// into a *resource.Resource ready for ResourceAdminService.Create. It
// resolves BrokerProviderSlug → BrokerProviderID via the supplied index and
// enforces the slug/id mutual-exclusion contract.
func resourceConfigUnifiedToDomain(r config.ResourceConfigUnified, slugToID map[string]string) (*resource.Resource, error) {
	kind := resource.BackendKind(r.BackendKind)
	switch kind {
	case resource.BackendMint, resource.BackendBroker:
	default:
		return nil, fmt.Errorf("backend_kind must be mint or broker, got %q", r.BackendKind)
	}

	providerID := r.BrokerProviderID
	switch {
	case r.BrokerProviderID != "" && r.BrokerProviderSlug != "":
		return nil, fmt.Errorf("broker_provider_id and broker_provider_slug are mutually exclusive")
	case r.BrokerProviderSlug != "":
		id, ok := slugToID[r.BrokerProviderSlug]
		if !ok {
			return nil, fmt.Errorf("broker_provider_slug %q does not match any seeded broker_providers entry", r.BrokerProviderSlug)
		}
		providerID = id
	}
	if kind == resource.BackendBroker && providerID == "" {
		return nil, fmt.Errorf("broker_provider_id or broker_provider_slug is required for backend_kind: broker")
	}

	scopes := make([]resource.Scope, len(r.Scopes))
	for i, sc := range r.Scopes {
		scopes[i] = resource.Scope{
			Name:        sc.Name,
			Description: sc.Description,
			Upstream:    sc.Upstream,
		}
	}

	return &resource.Resource{
		Slug:             r.Slug,
		DisplayName:      r.DisplayName,
		URI:              r.URI,
		BackendKind:      kind,
		BrokerProviderID: providerID,
		Scopes:           scopes,
		Policy: resource.Policy{
			Exchange: resource.ExchangePolicy{
				AllowedClientIDs: r.Policy.Exchange.AllowedClientIDs,
			},
			Runtime: resource.RuntimePolicy{
				ClientIDs: r.Policy.Runtime.ClientIDs,
			},
			Connect: resource.ConnectPolicy{
				AllowedReturnURLs: r.Policy.Connect.AllowedReturnURLs,
			},
		},
	}, nil
}

// warnIfCORSDisabled emits a one-line startup warning when CORS is disabled but
// browser-facing OAuth endpoints are served (which is always — /oauth/authorize,
// /oauth/token, /oauth/introspect, and /oauth/revoke are unconditional). The
// warning includes a clear remediation hint so operators don't have to debug
// silent CORS preflight failures from browser-based MCP clients.
//
// This is intentionally a Warn (not a fatal): server-to-server-only deployments
// may legitimately run with no allowed origins.
func warnIfCORSDisabled(logger *slog.Logger, allowedOrigins []string) {
	if len(allowedOrigins) > 0 {
		return
	}
	logger.Warn(
		"CORS is disabled (AUTHPLANE_SERVER_ALLOWED_ORIGINS is empty); " +
			"browser-based MCP clients (MCP Inspector, Claude Desktop, etc.) " +
			"will silently fail on /oauth/token, /oauth/introspect, and /oauth/revoke " +
			"due to CORS preflight rejections. " +
			"For local dev set AUTHPLANE_SERVER_ALLOWED_ORIGINS=*; " +
			"for production set an explicit origin allowlist.",
	)
}

// probeSecretRefs verifies that the OIDC client secret configured by an env-var
// reference (oidc.client_secret_ref) has that env var set and non-empty, so a
// missing one fails fast at boot rather than at first login — restoring the
// boot-time check validate.go performed eagerly before OIDC secret resolution
// moved to the token exchange. It does NOT decrypt.
//
// Broker-provider *_ref secrets are intentionally NOT probed: they resolve
// lazily at vend (as they always have), and runtime admin-created providers
// can't be probed at boot, so a boot probe there would be an inconsistent,
// config-only guarantee.
func probeSecretRefs(cfg *config.Config) error {
	ref := cfg.OIDC.ClientSecretRef
	if ref == "" {
		return nil
	}
	// A ref carried over from the deprecated client_secret_env key predates the
	// naming rule (v0.1.x documented OIDC_CLIENT_SECRET and the like), so it is
	// probed for presence but exempt from the shape check. The boot-time
	// deprecation warning tells the operator to rename it.
	if legacy := cfg.LegacyOIDCSecretRef(); legacy == ref {
		if os.Getenv(ref) == "" {
			return fmt.Errorf("oidc.client_secret_env: env var %s is not set or empty", ref)
		}
		return nil
	}
	if !brokerproto.ValidEnvVarName(ref) {
		return fmt.Errorf(
			"oidc.client_secret_ref: %q is not an allowed secret env-var name (must use the CONNECTOR_* or AUTHPLANE_VAULT_* prefix required for every *_ref secret)",
			ref,
		)
	}
	if os.Getenv(ref) == "" {
		return fmt.Errorf("oidc.client_secret_ref: env var %s is not set or empty", ref)
	}
	return nil
}
