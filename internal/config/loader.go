package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/authplane/authserver/internal/domain/resource"
)

// legacyYAMLKeys names YAML keys removed by the unified-resources rewrite.
// Each entry's value is a short migration hint surfaced in the parse-time error
// so operators see the path forward without diving into the schema doc.
var legacyYAMLKeys = []struct {
	path string
	hint string
}{
	{"resource_servers", "use 'resources:' (top-level) with backend_kind: mint instead"},
	{"vault_connectors", "use 'broker_providers:' (top-level) instead"},
	{"vault_connect", "renamed to 'connect:'"},
	{"token_exchange.cross_client_allowlist", "fold into per-resource policy.exchange.allowed_client_ids"},
}

// Load loads configuration from a YAML file and environment variables.
// Priority: defaults < YAML file < environment variables.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // path is provided by the operator via --config CLI flag
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("read config file: %w", err)
			}
		} else {
			// Hard-fail on legacy YAML keys removed in the unified-resources rewrite. Pre-production
			// (no v0.1.0 tag shipped), there is no operator base to keep
			// parsing; auto-rewrite would risk silent semantic drift.
			if err := rejectLegacyYAMLKeys(data); err != nil {
				return nil, err
			}
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("parse config file: %w", err)
			}
		}
	}

	if err := loadFromEnv(cfg); err != nil {
		return nil, fmt.Errorf("load env config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// rejectLegacyYAMLKeys parses the raw YAML into a map[string]any and walks
// it for any of the four legacy keys retired in the unified-resources rewrite. Returns a structured
// error pointing at the migration table on the first match.
func rejectLegacyYAMLKeys(data []byte) error {
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		// Defer to the typed-Unmarshal call below for the actual parse error.
		// A separate failure here would obscure the real issue.
		return nil //nolint:nilerr // intentional: see comment above
	}
	for _, lk := range legacyYAMLKeys {
		if hasYAMLKey(raw, lk.path) {
			return fmt.Errorf(
				"config: legacy key %q removed in v0.1.0-rc1 — %s",
				lk.path, lk.hint,
			)
		}
	}
	return nil
}

// hasYAMLKey reports whether a `.`-delimited path is present in the parsed
// YAML map. Walks one segment at a time; non-map intermediate values stop the
// walk and return false.
func hasYAMLKey(raw map[string]interface{}, path string) bool {
	segments := strings.Split(path, ".")
	cur := raw
	for i, seg := range segments {
		v, ok := cur[seg]
		if !ok {
			return false
		}
		if i == len(segments)-1 {
			return true
		}
		next, ok := v.(map[string]interface{})
		if !ok {
			return false
		}
		cur = next
	}
	return false
}

// DefaultConfig returns sensible defaults for local development.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Issuer:       "http://localhost:9000",
			Address:      ":9000",
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
			ShutdownWait: 10 * time.Second,
		},
		Storage: StorageConfig{
			Driver: "sqlite",
			SQLite: SQLiteConfig{
				Path: "data/authserver.db",
				WAL:  true,
			},
			Postgres: PostgresConfig{
				MaxConns:        25,
				MinConns:        5,
				MaxConnLifetime: time.Hour,
				MaxConnIdleTime: 30 * time.Minute,
			},
		},
		Signing: SigningConfig{
			Algorithm: "ES256",
			KeyStore:  "keyfile",
			KeyPath:   "data/keys",
			VaultTransit: VaultTransitConfig{
				Mount:   "transit",
				KeyName: "authserver-signing",
				Timeout: 10 * time.Second,
			},
		},
		DCR: DCRConfig{
			Mode:                 "open",
			RateLimit:            10,
			RateLimitBurst:       20,
			DefaultTokenExpiry:   15 * time.Minute,
			DefaultRefreshExpiry: 7 * 24 * time.Hour,
		},
		CIMD: CIMDConfig{
			Enabled:      true,
			RequireHTTPS: true,
			CacheTTL:     time.Hour,
			FetchTimeout: 10 * time.Second,
		},
		Session: SessionConfig{
			CookieName: "authserver_session",
			MaxAge:     24 * time.Hour,
			Secure:     false,
			SameSite:   "lax",
			// Secure-by-default per 2026-05-18 follow-up audit. A transient
			// user-store error during session-cookie validation rejects the
			// session rather than silently letting the request through. Set
			// AUTHPLANE_SESSION_FAIL_CLOSED=false to revert (legacy behavior
			// preferred availability over revocation freshness).
			FailClosed: true,
		},
		RateLimit: RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100,
			Burst:             200,
			AuthFailMax:       10,
			AuthFailWindow:    10 * time.Minute,
			AuthLockout:       15 * time.Minute,
		},
		OAuth: OAuthConfig{
			RequireScope: true,
		},
		OIDC: OIDCConfig{
			ShowLocalLogin:     true,
			IncludeGroupsScope: true,
		},
		ClientCredentials: ClientCredentialsConfig{
			Enabled:     false,
			TokenExpiry: 1 * time.Hour,
		},
		DPoP: DPoPConfig{
			Enabled:       false,
			NonceTTL:      60 * time.Second,
			ProofLifetime: 60 * time.Second,
		},
		TokenExchange: TokenExchangeConfig{
			Enabled:       false,
			MaxChainDepth: 5,
			TokenExpiry:   1 * time.Hour,
		},
		Admin: AdminConfig{
			Enabled: true,
			Address: ":9001",
		},
		Observability: ObservabilityConfig{
			Logging: LoggingConfig{
				Level:  "info",
				Format: "json",
				Outputs: LogOutputs{
					Stdout: true,
				},
			},
			Metrics: MetricsConfig{
				Provider: "prometheus",
				Path:     "/metrics",
			},
			Tracing: TracingConfig{
				Enabled:    false,
				SampleRate: 1.0,
			},
		},
	}
}

func loadFromEnv(cfg *Config) error {
	loadServerFromEnv(&cfg.Server)
	loadStorageFromEnv(&cfg.Storage)
	loadSigningFromEnv(&cfg.Signing)
	loadDCRFromEnv(&cfg.DCR)
	loadCIMDFromEnv(&cfg.CIMD)
	loadSessionFromEnv(&cfg.Session)
	loadRateLimitFromEnv(&cfg.RateLimit)
	loadAdminFromEnv(&cfg.Admin)
	loadOAuthFromEnv(&cfg.OAuth)
	loadOIDCFromEnv(&cfg.OIDC)
	loadObservabilityFromEnv(&cfg.Observability)
	if err := loadResourcesFromEnv(cfg); err != nil {
		return err
	}
	loadClientCredentialsFromEnv(&cfg.ClientCredentials)
	loadDPoPFromEnv(&cfg.DPoP)
	loadTokenExchangeFromEnv(&cfg.TokenExchange)
	loadAgentsFromEnv(&cfg.Agents)
	loadDataEncryptionFromEnv(&cfg.DataEncryption)
	loadConnectFromEnv(&cfg.Connect)
	loadBrokerProviderFromEnv(cfg)
	cfg.ClientSecretPepper = getEnv("AUTHPLANE_CLIENT_SECRET_PEPPER", cfg.ClientSecretPepper)
	return nil
}

func loadClientCredentialsFromEnv(cfg *ClientCredentialsConfig) {
	cfg.Enabled = getEnvBool("AUTHPLANE_CLIENT_CREDENTIALS_ENABLED", cfg.Enabled)
	cfg.TokenExpiry = getEnvDuration("AUTHPLANE_CLIENT_CREDENTIALS_TOKEN_EXPIRY", cfg.TokenExpiry)
}

func loadDPoPFromEnv(cfg *DPoPConfig) {
	cfg.Enabled = getEnvBool("AUTHPLANE_DPOP_ENABLED", cfg.Enabled)
	cfg.NonceTTL = getEnvDuration("AUTHPLANE_DPOP_NONCE_TTL", cfg.NonceTTL)
	cfg.ProofLifetime = getEnvDuration("AUTHPLANE_DPOP_PROOF_LIFETIME", cfg.ProofLifetime)
	cfg.RequireNonce = getEnvBool("AUTHPLANE_DPOP_REQUIRE_NONCE", cfg.RequireNonce)
}

func loadTokenExchangeFromEnv(cfg *TokenExchangeConfig) {
	cfg.Enabled = getEnvBool("AUTHPLANE_TOKEN_EXCHANGE_ENABLED", cfg.Enabled)
	cfg.AllowSelfExchange = getEnvBool("AUTHPLANE_TOKEN_EXCHANGE_ALLOW_SELF_EXCHANGE", cfg.AllowSelfExchange)
	cfg.MaxChainDepth = getEnvInt("AUTHPLANE_TOKEN_EXCHANGE_MAX_CHAIN_DEPTH", cfg.MaxChainDepth)
	cfg.TokenExpiry = getEnvDuration("AUTHPLANE_TOKEN_EXCHANGE_TOKEN_EXPIRY", cfg.TokenExpiry)
}

func loadAgentsFromEnv(cfg *AgentsConfig) {
	cfg.EnableJWKSListing = getEnvBool("AUTHPLANE_AGENTS_ENABLE_JWKS_LISTING", cfg.EnableJWKSListing)
}

func loadDataEncryptionFromEnv(cfg *DataEncryptionConfig) {
	cfg.Driver = getEnv("AUTHPLANE_DATA_ENCRYPTION_DRIVER", cfg.Driver)
	cfg.AESMaster.KeyEnv = getEnv("AUTHPLANE_DATA_ENCRYPTION_KEY_ENV", cfg.AESMaster.KeyEnv)
	cfg.VaultTransitEncrypt.Address = getEnv("AUTHPLANE_DATA_ENCRYPTION_VAULT_ADDRESS", cfg.VaultTransitEncrypt.Address)
	cfg.VaultTransitEncrypt.AuthMethod = getEnv("AUTHPLANE_DATA_ENCRYPTION_VAULT_AUTH_METHOD", cfg.VaultTransitEncrypt.AuthMethod)
	cfg.VaultTransitEncrypt.TokenEnv = getEnv("AUTHPLANE_DATA_ENCRYPTION_VAULT_TOKEN_ENV", cfg.VaultTransitEncrypt.TokenEnv)
	cfg.VaultTransitEncrypt.MountPath = getEnv("AUTHPLANE_DATA_ENCRYPTION_VAULT_MOUNT_PATH", cfg.VaultTransitEncrypt.MountPath)
	cfg.VaultTransitEncrypt.KeyName = getEnv("AUTHPLANE_DATA_ENCRYPTION_VAULT_KEY_NAME", cfg.VaultTransitEncrypt.KeyName)
	cfg.VaultTransitEncrypt.AppRole.RoleIDEnv = getEnv("AUTHPLANE_DATA_ENCRYPTION_VAULT_ROLE_ID_ENV", cfg.VaultTransitEncrypt.AppRole.RoleIDEnv)
	cfg.VaultTransitEncrypt.AppRole.SecretIDEnv = getEnv("AUTHPLANE_DATA_ENCRYPTION_VAULT_SECRET_ID_ENV", cfg.VaultTransitEncrypt.AppRole.SecretIDEnv)
}

func loadServerFromEnv(cfg *ServerConfig) {
	cfg.Issuer = getEnv("AUTHPLANE_SERVER_ISSUER", cfg.Issuer)
	cfg.Address = getEnv("AUTHPLANE_SERVER_ADDRESS", cfg.Address)
	cfg.ReadTimeout = getEnvDuration("AUTHPLANE_SERVER_READ_TIMEOUT", cfg.ReadTimeout)
	cfg.WriteTimeout = getEnvDuration("AUTHPLANE_SERVER_WRITE_TIMEOUT", cfg.WriteTimeout)
	cfg.IdleTimeout = getEnvDuration("AUTHPLANE_SERVER_IDLE_TIMEOUT", cfg.IdleTimeout)
	cfg.ShutdownWait = getEnvDuration("AUTHPLANE_SERVER_SHUTDOWN_WAIT", cfg.ShutdownWait)
	cfg.AllowedOrigins = getEnvStringSlice("AUTHPLANE_SERVER_ALLOWED_ORIGINS", cfg.AllowedOrigins)
}

func loadStorageFromEnv(cfg *StorageConfig) {
	cfg.Driver = getEnv("AUTHPLANE_STORAGE_DRIVER", cfg.Driver)
	cfg.SQLite.Path = getEnv("AUTHPLANE_STORAGE_SQLITE_PATH", cfg.SQLite.Path)
	cfg.SQLite.WAL = getEnvBool("AUTHPLANE_STORAGE_SQLITE_WAL", cfg.SQLite.WAL)
	cfg.Postgres.DSN = getEnv("AUTHPLANE_STORAGE_POSTGRES_DSN", cfg.Postgres.DSN)
	cfg.Postgres.MaxConns = getEnvInt("AUTHPLANE_STORAGE_POSTGRES_MAX_CONNS", cfg.Postgres.MaxConns)
	cfg.Postgres.MinConns = getEnvInt("AUTHPLANE_STORAGE_POSTGRES_MIN_CONNS", cfg.Postgres.MinConns)
	cfg.Postgres.MaxConnLifetime = getEnvDuration("AUTHPLANE_STORAGE_POSTGRES_MAX_CONN_LIFETIME", cfg.Postgres.MaxConnLifetime)
	cfg.Postgres.MaxConnIdleTime = getEnvDuration("AUTHPLANE_STORAGE_POSTGRES_MAX_CONN_IDLE_TIME", cfg.Postgres.MaxConnIdleTime)
}

func loadSigningFromEnv(cfg *SigningConfig) {
	cfg.Algorithm = getEnv("AUTHPLANE_SIGNING_ALGORITHM", cfg.Algorithm)
	cfg.KeyStore = getEnv("AUTHPLANE_SIGNING_KEY_STORE", cfg.KeyStore)
	cfg.KeyPath = getEnv("AUTHPLANE_SIGNING_KEY_PATH", cfg.KeyPath)
	cfg.VaultTransit.Address = getEnv("AUTHPLANE_VAULT_ADDR", cfg.VaultTransit.Address)
	cfg.VaultTransit.Token = getEnv("AUTHPLANE_VAULT_TOKEN", cfg.VaultTransit.Token)
	cfg.VaultTransit.Mount = getEnv("AUTHPLANE_VAULT_TRANSIT_MOUNT", cfg.VaultTransit.Mount)
	cfg.VaultTransit.KeyName = getEnv("AUTHPLANE_VAULT_TRANSIT_KEY_NAME", cfg.VaultTransit.KeyName)
	cfg.VaultTransit.Timeout = getEnvDuration("AUTHPLANE_VAULT_TIMEOUT", cfg.VaultTransit.Timeout)
	cfg.VaultTransit.AppRole.RoleID = getEnv("AUTHPLANE_VAULT_APPROLE_ROLE_ID", cfg.VaultTransit.AppRole.RoleID)
	cfg.VaultTransit.AppRole.SecretID = getEnv("AUTHPLANE_VAULT_APPROLE_SECRET_ID", cfg.VaultTransit.AppRole.SecretID)
	cfg.VaultTransit.AppRole.Mount = getEnv("AUTHPLANE_VAULT_APPROLE_MOUNT", cfg.VaultTransit.AppRole.Mount)
	cfg.PostgresKey.EncryptionKeyEnv = getEnv("AUTHPLANE_SIGNING_PG_ENCRYPTION_KEY_ENV", cfg.PostgresKey.EncryptionKeyEnv)
}

func loadDCRFromEnv(cfg *DCRConfig) {
	cfg.Mode = getEnv("AUTHPLANE_DCR_MODE", cfg.Mode)
	cfg.ApprovedRedirects = getEnvStringSlice("AUTHPLANE_DCR_APPROVED_REDIRECTS", cfg.ApprovedRedirects)
	cfg.RateLimit = getEnvFloat64("AUTHPLANE_DCR_RATE_LIMIT", cfg.RateLimit)
	cfg.RateLimitBurst = getEnvInt("AUTHPLANE_DCR_RATE_LIMIT_BURST", cfg.RateLimitBurst)
	cfg.DefaultTokenExpiry = getEnvDuration("AUTHPLANE_DCR_DEFAULT_TOKEN_EXPIRY", cfg.DefaultTokenExpiry)
	cfg.DefaultRefreshExpiry = getEnvDuration("AUTHPLANE_DCR_DEFAULT_REFRESH_EXPIRY", cfg.DefaultRefreshExpiry)
}

func loadCIMDFromEnv(cfg *CIMDConfig) {
	cfg.Enabled = getEnvBool("AUTHPLANE_CIMD_ENABLED", cfg.Enabled)
	cfg.RequireHTTPS = getEnvBool("AUTHPLANE_CIMD_REQUIRE_HTTPS", cfg.RequireHTTPS)
	cfg.CacheTTL = getEnvDuration("AUTHPLANE_CIMD_CACHE_TTL", cfg.CacheTTL)
	cfg.FetchTimeout = getEnvDuration("AUTHPLANE_CIMD_FETCH_TIMEOUT", cfg.FetchTimeout)
}

func loadSessionFromEnv(cfg *SessionConfig) {
	cfg.CookieName = getEnv("AUTHPLANE_SESSION_COOKIE_NAME", cfg.CookieName)
	cfg.MaxAge = getEnvDuration("AUTHPLANE_SESSION_MAX_AGE", cfg.MaxAge)
	cfg.Secure = getEnvBool("AUTHPLANE_SESSION_SECURE", cfg.Secure)
	cfg.SameSite = getEnv("AUTHPLANE_SESSION_SAME_SITE", cfg.SameSite)
	cfg.Secret = getEnv("AUTHPLANE_SESSION_SECRET", cfg.Secret)
	cfg.FailClosed = getEnvBool("AUTHPLANE_SESSION_FAIL_CLOSED", cfg.FailClosed)
}

func loadRateLimitFromEnv(cfg *RateLimitConfig) {
	cfg.Enabled = getEnvBool("AUTHPLANE_RATE_LIMIT_ENABLED", cfg.Enabled)
	cfg.RequestsPerSecond = getEnvFloat64("AUTHPLANE_RATE_LIMIT_RPS", cfg.RequestsPerSecond)
	cfg.Burst = getEnvInt("AUTHPLANE_RATE_LIMIT_BURST", cfg.Burst)
	cfg.AuthFailMax = getEnvInt("AUTHPLANE_RATE_LIMIT_AUTH_FAIL_MAX", cfg.AuthFailMax)
	cfg.AuthFailWindow = getEnvDuration("AUTHPLANE_RATE_LIMIT_AUTH_FAIL_WINDOW", cfg.AuthFailWindow)
	cfg.AuthLockout = getEnvDuration("AUTHPLANE_RATE_LIMIT_AUTH_LOCKOUT", cfg.AuthLockout)
}

func loadAdminFromEnv(cfg *AdminConfig) {
	cfg.Enabled = getEnvBool("AUTHPLANE_ADMIN_ENABLED", cfg.Enabled)
	cfg.Address = getEnv("AUTHPLANE_ADMIN_ADDRESS", cfg.Address)
	cfg.APIKey = getEnv("AUTHPLANE_ADMIN_API_KEY", cfg.APIKey)
}

func loadOAuthFromEnv(cfg *OAuthConfig) {
	cfg.RequireScope = getEnvBool("AUTHPLANE_OAUTH_REQUIRE_SCOPE", cfg.RequireScope)
}

func loadOIDCFromEnv(cfg *OIDCConfig) {
	cfg.Enabled = getEnvBool("AUTHPLANE_OIDC_ENABLED", cfg.Enabled)
	cfg.Issuer = getEnv("AUTHPLANE_OIDC_ISSUER", cfg.Issuer)
	cfg.ClientID = getEnv("AUTHPLANE_OIDC_CLIENT_ID", cfg.ClientID)
	cfg.ClientSecret = getEnv("AUTHPLANE_OIDC_CLIENT_SECRET", cfg.ClientSecret)
	cfg.DisplayName = getEnv("AUTHPLANE_OIDC_DISPLAY_NAME", cfg.DisplayName)
	cfg.Scopes = getEnvStringSlice("AUTHPLANE_OIDC_SCOPES", cfg.Scopes)
	cfg.RedirectURI = getEnv("AUTHPLANE_OIDC_REDIRECT_URI", cfg.RedirectURI)
	cfg.ShowLocalLogin = getEnvBool("AUTHPLANE_OIDC_SHOW_LOCAL_LOGIN", cfg.ShowLocalLogin)
	cfg.IncludeGroupsScope = getEnvBool("AUTHPLANE_OIDC_INCLUDE_GROUPS_SCOPE", cfg.IncludeGroupsScope)
	cfg.ConnectorID = getEnv("AUTHPLANE_OIDC_CONNECTOR_ID", cfg.ConnectorID)
}

func loadObservabilityFromEnv(cfg *ObservabilityConfig) {
	cfg.Logging.Level = getEnv("AUTHPLANE_LOG_LEVEL", cfg.Logging.Level)
	cfg.Logging.Format = getEnv("AUTHPLANE_LOG_FORMAT", cfg.Logging.Format)
	cfg.Logging.AddSource = getEnvBool("AUTHPLANE_LOG_ADD_SOURCE", cfg.Logging.AddSource)
	cfg.Logging.Outputs.Stdout = getEnvBool("AUTHPLANE_LOG_STDOUT", cfg.Logging.Outputs.Stdout)
	cfg.Logging.Outputs.OTel = getEnvBool("AUTHPLANE_LOG_OTEL", cfg.Logging.Outputs.OTel)
	cfg.Logging.Outputs.OTelEndpoint = getEnv("AUTHPLANE_LOG_OTEL_ENDPOINT", cfg.Logging.Outputs.OTelEndpoint)
	cfg.Logging.Outputs.Insecure = getEnvBool("AUTHPLANE_LOG_OTEL_INSECURE", cfg.Logging.Outputs.Insecure)
	cfg.Metrics.Provider = getEnv("AUTHPLANE_METRICS_PROVIDER", cfg.Metrics.Provider)
	cfg.Metrics.Path = getEnv("AUTHPLANE_METRICS_PATH", cfg.Metrics.Path)
	cfg.Metrics.OTelEndpoint = getEnv("AUTHPLANE_METRICS_OTEL_ENDPOINT", cfg.Metrics.OTelEndpoint)
	cfg.Metrics.Insecure = getEnvBool("AUTHPLANE_METRICS_INSECURE", cfg.Metrics.Insecure)
	cfg.Tracing.Enabled = getEnvBool("AUTHPLANE_TRACING_ENABLED", cfg.Tracing.Enabled)
	cfg.Tracing.Endpoint = getEnv("AUTHPLANE_TRACING_ENDPOINT", cfg.Tracing.Endpoint)
	cfg.Tracing.Insecure = getEnvBool("AUTHPLANE_TRACING_INSECURE", cfg.Tracing.Insecure)
	cfg.Tracing.SampleRate = getEnvFloat64("AUTHPLANE_TRACING_SAMPLE_RATE", cfg.Tracing.SampleRate)
}

// --- env helpers ---

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val, ok := os.LookupEnv(key); ok {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	if val, ok := os.LookupEnv(key); ok {
		lower := strings.ToLower(val)
		return lower == "true" || lower == "1" || lower == "yes"
	}
	return defaultVal
}

func getEnvFloat64(key string, defaultVal float64) float64 {
	if val, ok := os.LookupEnv(key); ok {
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			return f
		}
	}
	return defaultVal
}

func getEnvStringSlice(key string, defaultVal []string) []string {
	if val, ok := os.LookupEnv(key); ok {
		if val == "" {
			return nil
		}
		return strings.Split(val, ",")
	}
	return defaultVal
}

func getEnvDuration(key string, defaultVal time.Duration) time.Duration {
	if val, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return defaultVal
}

func loadConnectFromEnv(cfg *ConnectConfig) {
	cfg.StateSecret = getEnv("AUTHPLANE_CONNECT_STATE_SECRET", cfg.StateSecret)
	cfg.RedirectBaseURL = getEnv("AUTHPLANE_CONNECT_REDIRECT_BASE_URL", cfg.RedirectBaseURL)
	cfg.AllowedReturnURLs = getEnvStringSlice("AUTHPLANE_CONNECT_ALLOWED_RETURN_URLS", cfg.AllowedReturnURLs)
}

// loadBrokerProviderFromEnv adds a single broker provider from env vars.
// AUTHPLANE_BROKER_PROVIDER_SLUG + related fields. Covers the common
// single-provider deployment; for multiple providers, use YAML.
//
// The fields populate BrokerProviderConfig.ConfigData, mirroring the YAML
// shape exactly so the seed loop's json.Marshal output matches what an
// operator would write by hand.
func loadBrokerProviderFromEnv(cfg *Config) {
	slug := getEnv("AUTHPLANE_BROKER_PROVIDER_SLUG", "")
	if slug == "" {
		return
	}
	// Use os.LookupEnv so we can distinguish "operator did not set the env
	// var" from "operator explicitly set it to the same string as slug" —
	// the latter must override a YAML DisplayName, the former must not.
	displayName, displayNameSet := os.LookupEnv("AUTHPLANE_BROKER_PROVIDER_DISPLAY_NAME")
	protocol, protocolSet := os.LookupEnv("AUTHPLANE_BROKER_PROVIDER_PROTOCOL")

	// Build config_data only with fields the operator actually set so
	// seed-time JSON marshaling matches an equivalent hand-written YAML.
	configData := map[string]interface{}{}
	if v := getEnv("AUTHPLANE_BROKER_PROVIDER_CLIENT_ID", ""); v != "" {
		configData["client_id"] = v
	}
	if v := getEnv("AUTHPLANE_BROKER_PROVIDER_CLIENT_SECRET_ENV", ""); v != "" {
		configData["client_secret_env"] = v
	}
	if v := getEnv("AUTHPLANE_BROKER_PROVIDER_AUTHORIZE_URL", ""); v != "" {
		configData["authorize_url"] = v
	}
	if v := getEnv("AUTHPLANE_BROKER_PROVIDER_TOKEN_URL", ""); v != "" {
		configData["token_url"] = v
	}
	if v := getEnv("AUTHPLANE_BROKER_PROVIDER_RESPONSE_FORMAT", ""); v != "" {
		configData["response_format"] = v
	}

	// If YAML already defined this slug, the env vars override matching
	// fields (mirrors loadResourcesFromEnv's merge semantics).
	for i := range cfg.BrokerProviders {
		bp := &cfg.BrokerProviders[i]
		if bp.Slug != slug {
			continue
		}
		if displayNameSet {
			bp.DisplayName = displayName
		} else if bp.DisplayName == "" {
			bp.DisplayName = slug
		}
		if protocolSet {
			bp.Protocol = protocol
		} else if bp.Protocol == "" {
			bp.Protocol = "oauth"
		}
		if bp.ConfigData == nil {
			bp.ConfigData = map[string]interface{}{}
		}
		for k, v := range configData {
			bp.ConfigData[k] = v
		}
		return
	}
	finalDisplayName := displayName
	if !displayNameSet {
		finalDisplayName = slug
	}
	finalProtocol := protocol
	if !protocolSet {
		finalProtocol = "oauth"
	}
	cfg.BrokerProviders = append(cfg.BrokerProviders, BrokerProviderConfig{
		Slug:        slug,
		DisplayName: finalDisplayName,
		Protocol:    finalProtocol,
		ConfigData:  configData,
	})
}

// loadResourcesFromEnv adds a single Mint resource from env vars.
// AUTHPLANE_RESOURCE_URI + AUTHPLANE_RESOURCE_SCOPES (comma-separated). This
// covers the common single-MCP-server deployment; for multiple resources or
// any Broker resource, use YAML config.
//
// The slug is derived from the URI deterministically (no operator input):
// url.Parse(URI).Hostname() → lowercase → runs of non-[a-z0-9] → '-' →
// trim → truncate(64) → resource.NormalizeSlug. Returns a structured
// error when the URI yields an empty/invalid slug so pathological hosts
// surface up front rather than at first vend.
func loadResourcesFromEnv(cfg *Config) error {
	uri := getEnv("AUTHPLANE_RESOURCE_URI", "")
	if uri == "" {
		return nil
	}
	slug, err := deriveSlugFromURI(uri)
	if err != nil {
		return fmt.Errorf("AUTHPLANE_RESOURCE_URI: %w", err)
	}
	scopeNames := getEnvStringSlice("AUTHPLANE_RESOURCE_SCOPES", nil)
	scopes := make([]ScopeConfig, len(scopeNames))
	for i, name := range scopeNames {
		scopes[i] = ScopeConfig{Name: name}
	}
	// If a YAML entry already defined this URI, env-supplied scopes
	// override the YAML list (mirrors the legacy merge semantics).
	for i, r := range cfg.Resources {
		if r.URI == uri {
			if len(scopes) > 0 {
				cfg.Resources[i].Scopes = scopes
			}
			return nil
		}
	}
	cfg.Resources = append(cfg.Resources, ResourceConfigUnified{
		Slug:        slug,
		URI:         uri,
		BackendKind: "mint",
		Scopes:      scopes,
	})
	return nil
}

// deriveSlugFromURI produces a deterministic slug from a Resource URI.
//
// Algorithm: url.Parse(URI).Hostname() → lowercase → runs of non-[a-z0-9]
// become a single '-' → trim leading/trailing '-' → truncate to 64 chars →
// run through resource.NormalizeSlug. Returns a structured error naming the
// URI and the derived-but-invalid slug if normalization fails.
func deriveSlugFromURI(uri string) (string, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("parse URI %q: %w", uri, err)
	}
	host := parsed.Hostname() // strips brackets + port
	if host == "" {
		return "", fmt.Errorf("URI %q has no host component for slug derivation", uri)
	}
	candidate := slugifyHost(host)
	if candidate == "" {
		return "", fmt.Errorf("URI %q produced empty slug after normalization", uri)
	}
	if len(candidate) > 64 {
		candidate = candidate[:64]
		// Truncation may leave a trailing '-' if the cut lands inside a run.
		for len(candidate) > 0 && candidate[len(candidate)-1] == '-' {
			candidate = candidate[:len(candidate)-1]
		}
	}
	slug, err := resource.NormalizeSlug(candidate)
	if err != nil {
		return "", fmt.Errorf("URI %q derived slug %q failed validation: %w", uri, candidate, err)
	}
	return slug, nil
}

// slugifyHost lowercases the host and replaces every run of non-[a-z0-9]
// runes with a single '-', trimming leading/trailing hyphens. The result
// still has to pass resource.NormalizeSlug; this just produces a candidate.
func slugifyHost(host string) string {
	out := make([]byte, 0, len(host))
	prevHyphen := true // suppress leading hyphens
	for i := 0; i < len(host); i++ {
		c := host[i]
		switch {
		case c >= 'A' && c <= 'Z':
			out = append(out, c+('a'-'A'))
			prevHyphen = false
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			out = append(out, c)
			prevHyphen = false
		default:
			if !prevHyphen {
				out = append(out, '-')
				prevHyphen = true
			}
		}
	}
	for len(out) > 0 && out[len(out)-1] == '-' {
		out = out[:len(out)-1]
	}
	return string(out)
}
