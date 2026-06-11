// Package config provides configuration loading and validation for authserver.
package config

import (
	"time"
)

// Config is the root configuration for the authserver server.
type Config struct {
	Server            ServerConfig            `yaml:"server"`
	Storage           StorageConfig           `yaml:"storage"`
	Signing           SigningConfig           `yaml:"signing"`
	DCR               DCRConfig               `yaml:"dcr"`
	CIMD              CIMDConfig              `yaml:"cimd"`
	Session           SessionConfig           `yaml:"session"`
	RateLimit         RateLimitConfig         `yaml:"rate_limit"`
	Admin             AdminConfig             `yaml:"admin"`
	OAuth             OAuthConfig             `yaml:"oauth"`
	OIDC              OIDCConfig              `yaml:"oidc"`
	Observability     ObservabilityConfig     `yaml:"observability"`
	Resources         []ResourceConfigUnified `yaml:"resources"`
	BrokerProviders   []BrokerProviderConfig  `yaml:"broker_providers"`
	DataEncryption    DataEncryptionConfig    `yaml:"data_encryption"`
	ClientCredentials ClientCredentialsConfig `yaml:"client_credentials"`
	DPoP              DPoPConfig              `yaml:"dpop"`
	TokenExchange     TokenExchangeConfig     `yaml:"token_exchange"`
	Agents            AgentsConfig            `yaml:"agents"`
	Connect           ConnectConfig           `yaml:"connect"`
	XAA               XAAConfig               `yaml:"xaa"`

	// ClientSecretPepper is the HMAC key for client-secret hashing.
	// When non-empty, client secrets are hashed/verified with HMAC-SHA256
	// instead of bcrypt; empty keeps bcrypt (the default). User passwords are
	// unaffected. Env: AUTHPLANE_CLIENT_SECRET_PEPPER.
	ClientSecretPepper string `yaml:"client_secret_pepper"`
}

// XAAConfig controls Enterprise-Managed Authorization (Cross App Access).
type XAAConfig struct {
	Enabled         bool          `yaml:"enabled"`
	TokenExpiry     time.Duration `yaml:"token_expiry"`      // TTL for XAA-issued access tokens (default: 1h)
	MaxAssertionAge time.Duration `yaml:"max_assertion_age"` // Max age of ID-JAG iat (default: 5m)
	RequireResource bool          `yaml:"require_resource"`  // Require resource claim in assertions (default: false)
	SubjectMode     string        `yaml:"subject_mode"`      // "auto_map" or "strict" (default: "auto_map")
	JWKSCacheTTL    time.Duration `yaml:"jwks_cache_ttl"`    // JWKS cache TTL (default: 1h)
}

// AgentsConfig controls agent identity features (Authplane extension).
type AgentsConfig struct {
	EnableJWKSListing bool `yaml:"enable_jwks_listing"` // expose agent list in JWKS endpoint (privacy: exposes client IDs publicly, default: false)
}

// OAuthConfig controls OAuth authorization server behavior.
type OAuthConfig struct {
	// RequireScope rejects authorize requests missing the scope parameter
	// with invalid_scope (RFC 6749 §3.3 compliant). When false, missing scope
	// defaults to all registered scopes for the resource (ADR-012).
	RequireScope bool `yaml:"require_scope"`
}

// OIDCConfig controls upstream OIDC federation (single provider, OSS).
type OIDCConfig struct {
	Enabled            bool     `yaml:"enabled"`
	Issuer             string   `yaml:"issuer"`               // upstream issuer URL (e.g., https://accounts.google.com)
	ClientID           string   `yaml:"client_id"`            // client_id registered with upstream IdP
	ClientSecret       string   `yaml:"client_secret"`        // client_secret registered with upstream IdP
	ClientSecretEnv    string   `yaml:"client_secret_env"`    // env var name for client_secret (takes precedence over client_secret)
	DisplayName        string   `yaml:"display_name"`         // button text, e.g. "Okta", "Google"
	Scopes             []string `yaml:"scopes"`               // OIDC scopes; defaults to ["openid","email","profile"]
	RedirectURI        string   `yaml:"redirect_uri"`         // explicit redirect_uri for OIDC callback
	ShowLocalLogin     bool     `yaml:"show_local_login"`     // show password form when OIDC is enabled (default true)
	IncludeGroupsScope bool     `yaml:"include_groups_scope"` // auto-include "groups" scope if upstream supports it (default true)
	ConnectorID        string   `yaml:"connector_id"`         // Dex connector_id parameter (optional)
}

// ServerConfig contains the main HTTP server settings.
type ServerConfig struct {
	Issuer         string        `yaml:"issuer"`
	Address        string        `yaml:"address"`
	ReadTimeout    time.Duration `yaml:"read_timeout"`
	WriteTimeout   time.Duration `yaml:"write_timeout"`
	IdleTimeout    time.Duration `yaml:"idle_timeout"`
	ShutdownWait   time.Duration `yaml:"shutdown_wait"`
	AllowedOrigins []string      `yaml:"allowed_origins"` // CORS allowed origins (empty = no CORS)
}

// StorageConfig selects and configures the storage backend.
type StorageConfig struct {
	Driver   string         `yaml:"driver"` // "sqlite" or "postgres"
	SQLite   SQLiteConfig   `yaml:"sqlite"`
	Postgres PostgresConfig `yaml:"postgres"`
}

// SQLiteConfig contains SQLite connection settings.
type SQLiteConfig struct {
	Path string `yaml:"path"`
	WAL  bool   `yaml:"wal"`
}

// PostgresConfig contains PostgreSQL connection settings.
type PostgresConfig struct {
	DSN             string        `yaml:"dsn"`
	MaxConns        int           `yaml:"max_conns"`
	MinConns        int           `yaml:"min_conns"`
	MaxConnLifetime time.Duration `yaml:"max_conn_lifetime"`
	MaxConnIdleTime time.Duration `yaml:"max_conn_idle_time"`
}

// SigningConfig controls JWT signing key generation and storage.
type SigningConfig struct {
	Algorithm    string             `yaml:"algorithm"`     // "ES256" or "RS256"
	KeyStore     string             `yaml:"key_store"`     // "keyfile" (default), "vault_transit", or "postgres_key"
	KeyPath      string             `yaml:"key_path"`      // path for keyfile store
	VaultTransit VaultTransitConfig `yaml:"vault_transit"` // Vault Transit config
	PostgresKey  PostgresKeyConfig  `yaml:"postgres_key"`  // PostgreSQL encrypted key store config
}

// PostgresKeyConfig controls the HA PostgreSQL signing key store.
// Keys are encrypted at rest via the configured DataEncryptor.
type PostgresKeyConfig struct {
	// EncryptionKeyEnv is the env var name for the key encryption key.
	// Only relevant when data_encryption.driver is aes_master.
	// The actual encryption uses the DataEncryptor port configured at the top level.
	EncryptionKeyEnv string `yaml:"encryption_key_env"`
}

// VaultTransitConfig controls Vault Transit signing.
type VaultTransitConfig struct {
	Address string        `yaml:"address"`  // Vault server address, e.g. "https://vault:8200"
	Token   string        `yaml:"token"`    // static Vault token (mutually exclusive with AppRole)
	Mount   string        `yaml:"mount"`    // transit engine mount path, default "transit"
	KeyName string        `yaml:"key_name"` // transit key name, default "authserver-signing"
	AppRole AppRoleConfig `yaml:"approle"`  // AppRole authentication
	Timeout time.Duration `yaml:"timeout"`  // HTTP request timeout, default 10s
}

// AppRoleConfig holds Vault AppRole authentication details.
type AppRoleConfig struct {
	RoleID   string `yaml:"role_id"`
	SecretID string `yaml:"secret_id"`
	Mount    string `yaml:"mount"` // auth mount, default "approle"
}

// DCRConfig controls Dynamic Client Registration behavior.
type DCRConfig struct {
	Mode                 string        `yaml:"mode"` // "open", "approved_redirects", "admin_only"
	ApprovedRedirects    []string      `yaml:"approved_redirects"`
	RateLimit            float64       `yaml:"rate_limit"`
	RateLimitBurst       int           `yaml:"rate_limit_burst"`
	DefaultTokenExpiry   time.Duration `yaml:"default_token_expiry"`
	DefaultRefreshExpiry time.Duration `yaml:"default_refresh_expiry"`
}

// CIMDConfig controls Client ID Metadata Document handling.
type CIMDConfig struct {
	Enabled      bool          `yaml:"enabled"`
	RequireHTTPS bool          `yaml:"require_https"`
	CacheTTL     time.Duration `yaml:"cache_ttl"`
	FetchTimeout time.Duration `yaml:"fetch_timeout"`
}

// SessionConfig controls user session cookies.
type SessionConfig struct {
	CookieName string        `yaml:"cookie_name"`
	MaxAge     time.Duration `yaml:"max_age"`
	Secure     bool          `yaml:"secure"`
	SameSite   string        `yaml:"same_site"` // "lax", "strict", "none"
	Secret     string        `yaml:"secret"`
	// FailClosed controls the session middleware's behavior on transient
	// user-store lookup errors. When true (default since the 2026-05-18
	// follow-up audit), any lookup error rejects the cookie — disabled
	// accounts cannot ride a transient DB outage. Set to false to restore
	// the pre-2026-05 behavior where DB blips keep sessions valid; do this
	// only when availability concerns outweigh revocation freshness.
	FailClosed bool `yaml:"fail_closed"`
}

// RateLimitConfig controls global rate limiting.
type RateLimitConfig struct {
	Enabled           bool          `yaml:"enabled"`
	RequestsPerSecond float64       `yaml:"requests_per_second"`
	Burst             int           `yaml:"burst"`
	AuthFailMax       int           `yaml:"auth_fail_max"`
	AuthFailWindow    time.Duration `yaml:"auth_fail_window"`
	AuthLockout       time.Duration `yaml:"auth_lockout"`
}

// AdminConfig controls the admin API server.
type AdminConfig struct {
	Enabled           bool    `yaml:"enabled"`
	Address           string  `yaml:"address"`
	APIKey            string  `yaml:"api_key"`
	RequestsPerSecond float64 `yaml:"requests_per_second"` // Per-IP rate limit (0 = no limit)
	Burst             int     `yaml:"burst"`               // Burst size for rate limiter
}

// ObservabilityConfig controls logging, tracing, and metrics.
type ObservabilityConfig struct {
	Logging LoggingConfig `yaml:"logging"`
	Metrics MetricsConfig `yaml:"metrics"`
	Tracing TracingConfig `yaml:"tracing"`
}

// LoggingConfig controls structured logging.
type LoggingConfig struct {
	Level     string     `yaml:"level"`  // "debug", "info", "warn", "error"
	Format    string     `yaml:"format"` // "json", "text"
	AddSource bool       `yaml:"add_source"`
	Outputs   LogOutputs `yaml:"outputs"`
}

// LogOutputs controls where log records are sent.
type LogOutputs struct {
	Stdout       bool   `yaml:"stdout"`        // Structured logs to stdout (default true)
	OTel         bool   `yaml:"otel"`          // Export logs via OTLP to OTel collector
	OTelEndpoint string `yaml:"otel_endpoint"` // OTLP gRPC endpoint for log export
	Insecure     bool   `yaml:"insecure"`      // Allow insecure gRPC for OTel logs
}

// MetricsConfig controls the metrics provider.
type MetricsConfig struct {
	Provider     string `yaml:"provider"`      // "prometheus", "otel", "none"
	Path         string `yaml:"path"`          // Prometheus scrape endpoint path
	OTelEndpoint string `yaml:"otel_endpoint"` // OTLP endpoint when provider=otel
	Insecure     bool   `yaml:"insecure"`      // Allow insecure gRPC for OTel metrics
}

// TracingConfig controls distributed tracing.
type TracingConfig struct {
	Enabled    bool    `yaml:"enabled"`
	Endpoint   string  `yaml:"endpoint"`
	Insecure   bool    `yaml:"insecure"`
	SampleRate float64 `yaml:"sample_rate"`
}

// ResourceConfigUnified describes a Mint or Broker resource for the seed
// loop. Mirrors the admin API's POST /admin/resources DTO with one
// operator-friendly addition: BrokerProviderSlug is a YAML-only alias for
// BrokerProviderID, resolved at seed-time so operators don't have to copy
// UUIDs across the `broker_providers:` and `resources:` YAML sections.
type ResourceConfigUnified struct {
	Slug               string        `yaml:"slug"`
	URI                string        `yaml:"uri"`
	BackendKind        string        `yaml:"backend_kind"`         // "mint" or "broker"
	BrokerProviderID   string        `yaml:"broker_provider_id"`   // exact id; mutually exclusive with broker_provider_slug
	BrokerProviderSlug string        `yaml:"broker_provider_slug"` // YAML-only alias; resolved at seed-time
	DisplayName        string        `yaml:"display_name"`
	Description        string        `yaml:"description"`
	Scopes             []ScopeConfig `yaml:"scopes"`
	Policy             PolicyConfig  `yaml:"policy"`
}

// ScopeConfig describes a single scope on a Resource. Upstream is the
// wire-format scope at the upstream provider; only meaningful for Broker
// resources.
type ScopeConfig struct {
	Name        string `yaml:"name"`
	Upstream    string `yaml:"upstream"`
	Description string `yaml:"description"`
}

// PolicyConfig holds per-Resource policy. Mirrors resource.Policy.
type PolicyConfig struct {
	Exchange ExchangePolicyConfig `yaml:"exchange"`
	Runtime  RuntimePolicyConfig  `yaml:"runtime"`
	Connect  ConnectPolicyConfig  `yaml:"connect"`
}

// ExchangePolicyConfig holds the token-exchange policy for a Resource.
type ExchangePolicyConfig struct {
	AllowedClientIDs []string `yaml:"allowed_client_ids"`
}

// RuntimePolicyConfig holds the runtime client_ids authorized to act AS this
// Resource at /oauth/token.. Empty list = default-deny.
type RuntimePolicyConfig struct {
	ClientIDs []string `yaml:"client_ids"`
}

// ConnectPolicyConfig holds the connect-flow policy for a Broker Resource.
type ConnectPolicyConfig struct {
	AllowedReturnURLs []string `yaml:"allowed_return_urls"`
}

// BrokerProviderConfig describes an upstream OAuth (or other protocol)
// provider that Broker Resources reference. Mirrors the admin API's
// POST /admin/broker-providers DTO. ConfigData is adapter-shaped JSON;
// the brokerproto adapter validates the schema lazily at first vend.
type BrokerProviderConfig struct {
	Slug        string                 `yaml:"slug"`
	DisplayName string                 `yaml:"display_name"`
	Protocol    string                 `yaml:"protocol"` // "oauth" | "api_key" | "service_account"
	ConfigData  map[string]interface{} `yaml:"config_data"`
}

// DataEncryptionConfig controls how sensitive data is encrypted at rest.
type DataEncryptionConfig struct {
	Driver              string                    `yaml:"driver"` // "aes_master" or "vault_transit_encrypt"
	AESMaster           AESMasterConfig           `yaml:"aes_master"`
	VaultTransitEncrypt VaultTransitEncryptConfig `yaml:"vault_transit_encrypt"`
}

// AESMasterConfig holds configuration for the AES-256-GCM master key driver.
type AESMasterConfig struct {
	// KeyEnv is the name of the env var containing the 64-hex-char (32-byte) master key.
	KeyEnv string `yaml:"key_env"`
	// OldKeyEnv is the name of the env var containing the previous master key (decrypt-only fallback).
	// Used during key rotation: set both key_env (new) and old_key_env (old), run re-encrypt, then remove old_key_env.
	OldKeyEnv string `yaml:"old_key_env"`
}

// VaultTransitEncryptConfig holds configuration for the Vault Transit encrypt driver.
type VaultTransitEncryptConfig struct {
	Address    string               `yaml:"address"`     // Vault address (e.g. https://vault:8200)
	AuthMethod string               `yaml:"auth_method"` // "token" or "approle"
	TokenEnv   string               `yaml:"token_env"`   // Env var for Vault token
	AppRole    DataEncAppRoleConfig `yaml:"approle"`
	MountPath  string               `yaml:"mount_path"` // Transit mount path (default: "transit")
	KeyName    string               `yaml:"key_name"`   // Transit key name
}

// DataEncAppRoleConfig holds Vault AppRole settings for data encryption.
// Uses env var names (not direct values) for secret injection.
type DataEncAppRoleConfig struct {
	RoleIDEnv   string `yaml:"role_id_env"`
	SecretIDEnv string `yaml:"secret_id_env"`
}

// ClientCredentialsConfig controls the client_credentials grant (RFC 6749 §4.4).
type ClientCredentialsConfig struct {
	Enabled     bool          `yaml:"enabled"`
	TokenExpiry time.Duration `yaml:"token_expiry"` // machine token TTL (default: 1h)
}

// DPoPConfig controls DPoP proof-of-possession (RFC 9449).
type DPoPConfig struct {
	Enabled       bool          `yaml:"enabled"`        // enable DPoP support (default: false)
	NonceTTL      time.Duration `yaml:"nonce_ttl"`      // TTL for server-issued nonces (default: 60s)
	ProofLifetime time.Duration `yaml:"proof_lifetime"` // max |now - iat| for proof freshness (default: 60s)
	RequireNonce  bool          `yaml:"require_nonce"`  // when true, all DPoP proofs must include server nonce (default: false)
}

// TokenExchangeConfig controls RFC 8693 token exchange.
type TokenExchangeConfig struct {
	Enabled           bool          `yaml:"enabled"`
	AllowSelfExchange bool          `yaml:"allow_self_exchange"` // when true, client may exchange its own token for narrower scope (default: false)
	MaxChainDepth     int           `yaml:"max_chain_depth"`     // maximum delegation chain depth (required when enabled, 1-10)
	TokenExpiry       time.Duration `yaml:"token_expiry"`        // TTL for exchanged tokens (required when enabled)
}

// ConnectConfig controls the upstream-connection OAuth connect flow.
type ConnectConfig struct {
	StateSecret       string   `yaml:"state_secret"` // HMAC key for state tokens (required, min 32 chars)
	AllowedReturnURLs []string `yaml:"allowed_return_urls"`
	RedirectBaseURL   string   `yaml:"redirect_base_url"` // Base URL for OAuth callbacks
}
