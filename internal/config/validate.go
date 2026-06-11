package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// connectorIDRegexp validates the oidc.connector_id field (Dex connector selection).
var connectorIDRegexp = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)

// Validate checks the configuration for required fields and consistency.
func (c *Config) Validate() error {
	var errs []error

	if c.Server.Issuer == "" {
		errs = append(errs, errors.New("server.issuer is required"))
	}
	if c.Server.Address == "" {
		errs = append(errs, errors.New("server.address is required"))
	}

	// Storage
	switch c.Storage.Driver {
	case "sqlite":
		if c.Storage.SQLite.Path == "" {
			errs = append(errs, errors.New("storage.sqlite.path is required when driver is sqlite"))
		}
	case "postgres":
		if c.Storage.Postgres.DSN == "" {
			errs = append(errs, errors.New("storage.postgres.dsn is required when driver is postgres"))
		}
		// only enforce min<=max when both are explicitly set; zero
		// means "use pgx default" and should not interact with the bound check.
		if c.Storage.Postgres.MinConns > 0 && c.Storage.Postgres.MaxConns > 0 &&
			c.Storage.Postgres.MinConns > c.Storage.Postgres.MaxConns {
			errs = append(errs, fmt.Errorf("storage.postgres.min_conns (%d) must be <= max_conns (%d)",
				c.Storage.Postgres.MinConns, c.Storage.Postgres.MaxConns))
		}
	default:
		errs = append(errs, fmt.Errorf("storage.driver must be sqlite or postgres, got %q", c.Storage.Driver))
	}

	// Signing
	switch c.Signing.Algorithm {
	case "ES256", "RS256":
		// ok
	default:
		errs = append(errs, fmt.Errorf("signing.algorithm must be ES256 or RS256, got %q", c.Signing.Algorithm))
	}
	switch c.Signing.KeyStore {
	case "keyfile", "":
		if c.Signing.KeyPath == "" {
			errs = append(errs, errors.New("signing.key_path is required when key_store is keyfile"))
		}
	case "vault_transit":
		vt := c.Signing.VaultTransit
		if vt.Address == "" {
			errs = append(errs, errors.New("signing.vault_transit.address is required when key_store is vault_transit"))
		}
		if vt.Token == "" && vt.AppRole.RoleID == "" {
			errs = append(errs, errors.New("signing.vault_transit requires either token or approle.role_id"))
		}
		if vt.Token != "" && vt.AppRole.RoleID != "" {
			errs = append(errs, errors.New("signing.vault_transit: token and approle are mutually exclusive"))
		}
		if vt.AppRole.RoleID != "" && vt.AppRole.SecretID == "" {
			errs = append(errs, errors.New("signing.vault_transit.approle.secret_id is required when role_id is set"))
		}
	case "postgres_key":
		if c.Storage.Driver != "postgres" {
			errs = append(errs, errors.New("signing.key_store=postgres_key requires storage.driver=postgres"))
		}
		if c.DataEncryption.Driver == "" {
			errs = append(errs, errors.New("signing.key_store=postgres_key requires data_encryption to be configured"))
		}
	default:
		errs = append(errs, fmt.Errorf("signing.key_store must be keyfile, vault_transit, or postgres_key, got %q", c.Signing.KeyStore))
	}

	// DCR mode
	switch c.DCR.Mode {
	case "open", "admin_only":
		// ok
	case "approved_redirects":
		if len(c.DCR.ApprovedRedirects) == 0 {
			errs = append(errs, errors.New("dcr.approved_redirects must not be empty when dcr.mode is approved_redirects"))
		}
	default:
		errs = append(errs, fmt.Errorf("dcr.mode must be open, approved_redirects, or admin_only, got %q", c.DCR.Mode))
	}

	// Session secret — required when issuer is not localhost (production)
	if c.Session.Secret == "" && !isLocalhostIssuer(c.Server.Issuer) {
		errs = append(errs, errors.New("session.secret is required when server.issuer is not localhost"))
	} else if c.Session.Secret != "" && isWeakSecret(c.Session.Secret) {
		errs = append(errs, errors.New("session.secret is a known weak/default value — generate a strong random secret (e.g. openssl rand -hex 32)"))
	} else if c.Session.Secret != "" && !isLocalhostIssuer(c.Server.Issuer) && len(c.Session.Secret) < 16 {
		errs = append(errs, errors.New("session.secret must be at least 16 characters in production"))
	}

	// Session secure — required for production
	if !c.Session.Secure && !isLocalhostIssuer(c.Server.Issuer) {
		errs = append(errs, errors.New("session.secure must be true when server.issuer is not localhost"))
	}

	// Admin API key — required when admin is enabled in production
	if c.Admin.Enabled && c.Admin.APIKey == "" && !isLocalhostIssuer(c.Server.Issuer) {
		errs = append(errs, errors.New("admin.api_key is required when admin is enabled and server.issuer is not localhost"))
	} else if c.Admin.Enabled && c.Admin.APIKey != "" && isWeakSecret(c.Admin.APIKey) {
		errs = append(errs, errors.New("admin.api_key is a known weak/default value — generate a strong random key (e.g. openssl rand -hex 32)"))
	} else if c.Admin.Enabled && c.Admin.APIKey != "" && !isLocalhostIssuer(c.Server.Issuer) && len(c.Admin.APIKey) < 16 {
		errs = append(errs, errors.New("admin.api_key must be at least 16 characters in production"))
	}

	// Session same_site
	switch strings.ToLower(c.Session.SameSite) {
	case "lax", "strict", "none":
		// ok
	default:
		errs = append(errs, fmt.Errorf("session.same_site must be lax, strict, or none, got %q", c.Session.SameSite))
	}

	// Observability — logging
	switch strings.ToLower(c.Observability.Logging.Level) {
	case "debug", "info", "warn", "error":
		// ok
	default:
		errs = append(errs, fmt.Errorf("observability.logging.level must be debug, info, warn, or error, got %q", c.Observability.Logging.Level))
	}

	switch strings.ToLower(c.Observability.Logging.Format) {
	case "json", "text":
		// ok
	default:
		errs = append(errs, fmt.Errorf("observability.logging.format must be json or text, got %q", c.Observability.Logging.Format))
	}

	// Observability — tracing sample rate
	if c.Observability.Tracing.SampleRate < 0 || c.Observability.Tracing.SampleRate > 1 {
		errs = append(errs, fmt.Errorf("observability.tracing.sample_rate must be between 0.0 and 1.0, got %f", c.Observability.Tracing.SampleRate))
	}

	// Observability — log OTel output
	if c.Observability.Logging.Outputs.OTel && c.Observability.Logging.Outputs.OTelEndpoint == "" {
		errs = append(errs, errors.New("observability.logging.outputs.otel_endpoint is required when logging outputs otel is enabled"))
	}

	// Observability — metrics
	switch c.Observability.Metrics.Provider {
	case "prometheus", "otel", "both", "none":
		// ok
	default:
		errs = append(errs, fmt.Errorf("observability.metrics.provider must be prometheus, otel, both, or none, got %q", c.Observability.Metrics.Provider))
	}

	if c.Observability.Tracing.Enabled && c.Observability.Tracing.Endpoint == "" {
		errs = append(errs, errors.New("observability.tracing.endpoint is required when tracing is enabled"))
	}

	if (c.Observability.Metrics.Provider == "otel" || c.Observability.Metrics.Provider == "both") && c.Observability.Metrics.OTelEndpoint == "" {
		errs = append(errs, errors.New("observability.metrics.otel_endpoint is required when metrics provider is otel or both"))
	}

	// OIDC upstream federation
	if c.OIDC.Enabled {
		if c.OIDC.Issuer == "" {
			errs = append(errs, errors.New("oidc.issuer is required when oidc is enabled"))
		}
		if c.OIDC.ClientID == "" {
			errs = append(errs, errors.New("oidc.client_id is required when oidc is enabled"))
		}
		// Resolve client_secret_env (takes precedence over client_secret).
		if c.OIDC.ClientSecretEnv != "" {
			val := os.Getenv(c.OIDC.ClientSecretEnv)
			if val == "" {
				errs = append(errs, fmt.Errorf("oidc.client_secret_env: env var %s is not set or empty", c.OIDC.ClientSecretEnv))
			} else {
				c.OIDC.ClientSecret = val
			}
		}
		if c.OIDC.ClientSecret == "" {
			errs = append(errs, errors.New("oidc.client_secret is required when oidc is enabled"))
		}
		if c.OIDC.Issuer != "" && !strings.HasPrefix(c.OIDC.Issuer, "https://") && !isLocalhostIssuer(c.OIDC.Issuer) {
			errs = append(errs, errors.New("oidc.issuer must use HTTPS in production"))
		}
		if c.OIDC.RedirectURI == "" {
			errs = append(errs, errors.New("oidc.redirect_uri is required when oidc is enabled"))
		} else if !isLocalhostIssuer(c.Server.Issuer) && !strings.HasPrefix(c.OIDC.RedirectURI, "https://") {
			errs = append(errs, errors.New("oidc.redirect_uri must use HTTPS in production"))
		}
		if c.OIDC.ConnectorID != "" && !connectorIDRegexp.MatchString(c.OIDC.ConnectorID) {
			errs = append(errs, fmt.Errorf("oidc.connector_id must be alphanumeric with hyphens, got %q", c.OIDC.ConnectorID))
		}
	}

	// Port conflict: server.address and admin.address must not collide.
	if c.Admin.Enabled && c.Server.Address != "" && c.Admin.Address != "" && c.Server.Address == c.Admin.Address {
		errs = append(errs, fmt.Errorf("server.address and admin.address must differ, both set to %q", c.Server.Address))
	}

	// Client credentials
	if c.ClientCredentials.Enabled {
		if c.ClientCredentials.TokenExpiry <= 0 {
			errs = append(errs, errors.New("client_credentials.token_expiry must be positive when client_credentials is enabled"))
		}
	}

	// DPoP
	if c.DPoP.Enabled {
		if c.DPoP.NonceTTL <= 0 {
			errs = append(errs, errors.New("dpop.nonce_ttl must be positive when dpop is enabled"))
		}
		if c.DPoP.ProofLifetime < 10*time.Second || c.DPoP.ProofLifetime > 300*time.Second {
			errs = append(errs, fmt.Errorf("dpop.proof_lifetime must be between 10s and 300s, got %s", c.DPoP.ProofLifetime))
		}
	}

	// Token exchange
	if c.TokenExchange.Enabled {
		if c.TokenExchange.MaxChainDepth < 1 || c.TokenExchange.MaxChainDepth > 10 {
			errs = append(errs, fmt.Errorf("token_exchange.max_chain_depth must be between 1 and 10, got %d", c.TokenExchange.MaxChainDepth))
		}
		if c.TokenExchange.TokenExpiry <= 0 {
			errs = append(errs, errors.New("token_exchange.token_expiry must be positive when token_exchange is enabled"))
		}
	}

	// Data encryption
	errs = append(errs, c.validateDataEncryption()...)

	// Upstream connect flow (state secret etc — providers themselves are
	// validated by the brokerproto adapter at first vend, not at config-load
	// time).
	errs = append(errs, c.validateConnect()...)

	if len(errs) > 0 {
		return &ValidationErrors{Errors: errs}
	}
	return nil
}

// validateDataEncryption validates the data_encryption config block.
// Returns nil slice if no driver is configured (encryption is optional).
func (c *Config) validateDataEncryption() []error {
	var errs []error

	switch c.DataEncryption.Driver {
	case "":
		// No encryption configured — valid for dev, no further checks.
	case "aes_master":
		errs = append(errs, c.validateAESMasterConfig()...)
	case "vault_transit_encrypt":
		errs = append(errs, c.validateVaultTransitEncryptConfig()...)
	default:
		errs = append(errs, fmt.Errorf("data_encryption.driver must be aes_master or vault_transit_encrypt, got %q", c.DataEncryption.Driver))
	}

	return errs
}

func (c *Config) validateAESMasterConfig() []error {
	var errs []error

	keyEnv := c.DataEncryption.AESMaster.KeyEnv
	if keyEnv == "" {
		errs = append(errs, errors.New("data_encryption.aes_master.key_env must be set when driver is aes_master"))
		return errs
	}

	// Resolve the env var and validate key format.
	keyVal := os.Getenv(keyEnv)
	if keyVal == "" {
		errs = append(errs, fmt.Errorf("data_encryption.aes_master: env var %s is not set or empty", keyEnv))
		return errs
	}

	keyBytes, err := hex.DecodeString(keyVal)
	if err != nil {
		errs = append(errs, fmt.Errorf("data_encryption.aes_master: env var %s is not valid hex", keyEnv))
		return errs
	}

	if len(keyBytes) != 32 {
		errs = append(errs, fmt.Errorf("data_encryption.aes_master: env var %s must be exactly 64 hex chars (32 bytes), got %d hex chars", keyEnv, len(keyVal)))
	}

	// Validate old_key_env if set (decrypt-only fallback for key rotation).
	oldKeyEnv := c.DataEncryption.AESMaster.OldKeyEnv
	if oldKeyEnv != "" {
		oldKeyVal := os.Getenv(oldKeyEnv)
		if oldKeyVal == "" {
			errs = append(errs, fmt.Errorf("data_encryption.aes_master: env var %s (old_key_env) is not set or empty", oldKeyEnv))
		} else {
			oldKeyBytes, oldErr := hex.DecodeString(oldKeyVal)
			if oldErr != nil {
				errs = append(errs, fmt.Errorf("data_encryption.aes_master: env var %s (old_key_env) is not valid hex", oldKeyEnv))
			} else if len(oldKeyBytes) != 32 {
				errs = append(errs, fmt.Errorf("data_encryption.aes_master: env var %s (old_key_env) must be exactly 64 hex chars (32 bytes), got %d hex chars", oldKeyEnv, len(oldKeyVal)))
			} else if keyVal == oldKeyVal {
				errs = append(errs, fmt.Errorf("data_encryption.aes_master: old_key_env must be different from key_env"))
			}
		}
	}

	return errs
}

func (c *Config) validateVaultTransitEncryptConfig() []error {
	var errs []error

	vtc := c.DataEncryption.VaultTransitEncrypt

	if vtc.Address == "" {
		errs = append(errs, errors.New("data_encryption.vault_transit_encrypt.address is required when driver is vault_transit_encrypt"))
	}

	if vtc.KeyName == "" {
		errs = append(errs, errors.New("data_encryption.vault_transit_encrypt.key_name is required when driver is vault_transit_encrypt"))
	}

	switch vtc.AuthMethod {
	case "", "token":
		// token auth: token_env should be set but we don't require it
		// (Vault agent might inject the token via other means).
	case "approle":
		if vtc.AppRole.RoleIDEnv == "" {
			errs = append(errs, errors.New("data_encryption.vault_transit_encrypt.approle.role_id_env is required when auth_method is approle"))
		}
		if vtc.AppRole.SecretIDEnv == "" {
			errs = append(errs, errors.New("data_encryption.vault_transit_encrypt.approle.secret_id_env is required when auth_method is approle"))
		}
	default:
		errs = append(errs, fmt.Errorf("data_encryption.vault_transit_encrypt.auth_method must be token or approle, got %q", vtc.AuthMethod))
	}

	return errs
}

// ValidationErrors contains multiple validation errors.
type ValidationErrors struct {
	Errors []error
}

func (e *ValidationErrors) Error() string {
	var sb strings.Builder
	sb.WriteString("configuration validation failed:\n")
	for i, err := range e.Errors {
		fmt.Fprintf(&sb, "  %d. %s\n", i+1, err.Error())
	}
	return sb.String()
}

func (e *ValidationErrors) Unwrap() []error {
	return e.Errors
}

// validateConnect validates the connect: block (the upstream-connection
// state-secret + redirect surface). Per-provider URL/secret validation
// is owned by the brokerproto adapter at first vend.
//
// state_secret is required to be at least 32 characters when the connect
// flow is enabled (any non-empty value enables it via the
// connectionsEnabled predicate in cmd/authserver/serve.go). An empty
// state_secret disables the connect flow entirely and skips the length
// check — operators with no upstream-connection deployments don't have
// to set it.
func (c *Config) validateConnect() []error {
	var errs []error

	if c.Connect.StateSecret != "" && len(c.Connect.StateSecret) < 32 {
		errs = append(errs, errors.New("connect.state_secret must be at least 32 characters when set (generate with `openssl rand -hex 32`)"))
	}

	if c.Connect.RedirectBaseURL != "" {
		if err := validateConnectorURL(c.Connect.RedirectBaseURL); err != nil {
			errs = append(errs, fmt.Errorf("connect.redirect_base_url: %w", err))
		}
	}
	return errs
}

// validateConnectorURL checks that a connector URL is HTTPS (or HTTP for localhost in dev).
func validateConnectorURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && isLocalhostHost(parsed.Hostname()) {
		return nil
	}
	return fmt.Errorf("must be HTTPS (or HTTP for localhost), got %q", rawURL)
}

// isLocalhostHost checks if the hostname is a localhost address.
func isLocalhostHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// weakSecrets is a blocklist of known insecure default values that must be rejected.
var weakSecrets = []string{
	"dev-secret-change-me",
	"dev-admin-key",
	"changeme",
	"secret",
	"password",
	"admin",
	"test",
}

// isWeakSecret checks whether the value matches a known weak/default secret.
func isWeakSecret(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	for _, weak := range weakSecrets {
		if v == weak {
			return true
		}
	}
	return false
}

// isLocalhostIssuer returns true if the issuer URL points to localhost.
// Checks that the host portion is exactly localhost, 127.0.0.1, or [::1]
// (not e.g. localhost.evil.com).
func isLocalhostIssuer(issuer string) bool {
	for _, prefix := range []string{
		"http://localhost",
		"https://localhost",
		"http://127.0.0.1",
		"https://127.0.0.1",
		"http://[::1]",
		"https://[::1]",
	} {
		if !strings.HasPrefix(issuer, prefix) {
			continue
		}
		// After the prefix, only allow end-of-string, ':', or '/'.
		rest := issuer[len(prefix):]
		if rest == "" || rest[0] == ':' || rest[0] == '/' {
			return true
		}
	}
	return false
}
