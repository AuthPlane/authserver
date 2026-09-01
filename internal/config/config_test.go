package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfigIsValid(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultConfig should be valid: %v", err)
	}
}

// Pin the secure-by-default session policy from the 2026-05-18 follow-up
// audit. A regression that flips this back to false (e.g. someone replaces
// the literal with zero-value SessionConfig{} thinking it's equivalent) would
// silently restore the old availability-over-revocation behavior. ADV6
// rationale: tests must assert state, not just shape — pinning the value here
// catches the "did anyone change this?" case.
func TestDefaultConfig_SessionFailClosed_TrueByDefault(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.Session.FailClosed {
		t.Fatal("DefaultConfig().Session.FailClosed must be true (secure by default since 2026-05-18 audit follow-up). Set AUTHPLANE_SESSION_FAIL_CLOSED=false at the deployment to opt out, do not change the default.")
	}
}

func TestValidateRequiresIssuer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Issuer = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for empty issuer")
	}
	if !strings.Contains(err.Error(), "server.issuer") {
		t.Errorf("error should mention server.issuer: %v", err)
	}
}

func TestValidateRequiresAddress(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Address = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for empty address")
	}
	if !strings.Contains(err.Error(), "server.address") {
		t.Errorf("error should mention server.address: %v", err)
	}
}

func TestValidateStorageDriver(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Storage.Driver = "mysql"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for unsupported driver")
	}
	if !strings.Contains(err.Error(), "storage.driver") {
		t.Errorf("error should mention storage.driver: %v", err)
	}
}

func TestValidatePostgresDSNRequired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Storage.Driver = "postgres"
	cfg.Storage.Postgres.DSN = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for empty postgres DSN")
	}
	if !strings.Contains(err.Error(), "postgres.dsn") {
		t.Errorf("error should mention postgres.dsn: %v", err)
	}
}

// MinConns must not exceed MaxConns. Both > 0 to keep zero-means-default
// semantics intact.
func TestValidatePostgresMinConnsLEMaxConns(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Storage.Driver = "postgres"
	cfg.Storage.Postgres.DSN = "postgres://u:p@localhost/db"
	cfg.Storage.Postgres.MaxConns = 5
	cfg.Storage.Postgres.MinConns = 10
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for min_conns > max_conns")
	}
	if !strings.Contains(err.Error(), "min_conns") {
		t.Errorf("error should mention min_conns: %v", err)
	}
}

func TestValidateSigningAlgorithm(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Signing.Algorithm = "HS256"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
	if !strings.Contains(err.Error(), "signing.algorithm") {
		t.Errorf("error should mention signing.algorithm: %v", err)
	}
}

func TestValidateDCRModeApprovedRedirectsRequiresList(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DCR.Mode = "approved_redirects"
	cfg.DCR.ApprovedRedirects = nil
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for approved_redirects mode with empty list")
	}
	if !strings.Contains(err.Error(), "approved_redirects") {
		t.Errorf("error should mention approved_redirects: %v", err)
	}
}

func TestValidateDCRModeApprovedRedirectsWithList(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DCR.Mode = "approved_redirects"
	cfg.DCR.ApprovedRedirects = []string{"https://app.example.com/*"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("should be valid with non-empty approved_redirects: %v", err)
	}
}

func TestValidateSessionSecretRequiredForProduction(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Issuer = "https://auth.example.com"
	cfg.Session.Secret = ""
	cfg.Session.Secure = true
	cfg.Admin.APIKey = "test-admin-key-strong-enough"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for empty session secret in production")
	}
	if !strings.Contains(err.Error(), "session.secret") {
		t.Errorf("error should mention session.secret: %v", err)
	}
}

func TestValidateSessionSecureRequiredForProduction(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Issuer = "https://auth.example.com"
	cfg.Session.Secret = "test-secret-long-enough"
	cfg.Session.Secure = false
	cfg.Admin.APIKey = "test-admin-key-strong-enough"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for session.secure=false in production")
	}
	if !strings.Contains(err.Error(), "session.secure") {
		t.Errorf("error should mention session.secure: %v", err)
	}
}

func TestValidateAdminAPIKeyRequiredForProduction(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Issuer = "https://auth.example.com"
	cfg.Session.Secret = "test-secret-long-enough"
	cfg.Session.Secure = true
	cfg.Admin.Enabled = true
	cfg.Admin.APIKey = ""
	err := cfg.ValidateAdminAPIKey()
	if err == nil {
		t.Fatal("expected error for empty admin.api_key in production")
	}
	if !strings.Contains(err.Error(), "admin.api_key") {
		t.Errorf("error should mention admin.api_key: %v", err)
	}
}

func TestValidateSessionSecretOptionalForLocalhost(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Issuer = "http://localhost:9000"
	cfg.Session.Secret = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("session.secret should be optional for localhost: %v", err)
	}
}

func TestValidateMetricsProvider(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Observability.Metrics.Provider = "statsd"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for unsupported metrics provider")
	}
	if !strings.Contains(err.Error(), "metrics.provider") {
		t.Errorf("error should mention metrics.provider: %v", err)
	}
}

func TestValidateTracingEndpointRequired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Observability.Tracing.Enabled = true
	cfg.Observability.Tracing.Endpoint = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for enabled tracing without endpoint")
	}
	if !strings.Contains(err.Error(), "tracing.endpoint") {
		t.Errorf("error should mention tracing.endpoint: %v", err)
	}
}

func TestValidateMultipleErrors(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Issuer = ""
	cfg.Server.Address = ""
	cfg.Storage.Driver = "invalid"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation errors")
	}
	ve, ok := err.(*ValidationErrors)
	if !ok {
		t.Fatalf("expected *ValidationErrors, got %T", err)
	}
	if len(ve.Errors) < 3 {
		t.Errorf("expected at least 3 errors, got %d", len(ve.Errors))
	}
}

func TestEnvOverrideIssuer(t *testing.T) {
	t.Setenv("AUTHPLANE_SERVER_ISSUER", "https://auth.test.com")
	cfg := DefaultConfig()
	if err := loadFromEnv(cfg); err != nil {
		t.Fatalf("loadFromEnv: %v", err)
	}
	if cfg.Server.Issuer != "https://auth.test.com" {
		t.Errorf("Issuer = %q, want https://auth.test.com", cfg.Server.Issuer)
	}
}

func TestEnvOverrideStorageDriver(t *testing.T) {
	t.Setenv("AUTHPLANE_STORAGE_DRIVER", "postgres")
	cfg := DefaultConfig()
	if err := loadFromEnv(cfg); err != nil {
		t.Fatalf("loadFromEnv: %v", err)
	}
	if cfg.Storage.Driver != "postgres" {
		t.Errorf("Driver = %q, want postgres", cfg.Storage.Driver)
	}
}

func TestGetEnvBoolVariants(t *testing.T) {
	tests := []struct {
		val  string
		want bool
	}{
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"1", true},
		{"yes", true},
		{"YES", true},
		{"false", false},
		{"0", false},
		{"no", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.val, func(t *testing.T) {
			key := "TEST_BOOL_" + tt.val
			t.Setenv(key, tt.val)
			got := getEnvBool(key, false)
			if got != tt.want {
				t.Errorf("getEnvBool(%q) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}

func TestGetEnvBoolDefault(t *testing.T) {
	got := getEnvBool("NONEXISTENT_KEY_12345", true)
	if !got {
		t.Error("should return default when env var not set")
	}
}

func TestEnvOverrideApprovedRedirects(t *testing.T) {
	t.Setenv("AUTHPLANE_DCR_APPROVED_REDIRECTS", "https://a.example.com/cb,https://b.example.com/cb")
	cfg := DefaultConfig()
	if err := loadFromEnv(cfg); err != nil {
		t.Fatalf("loadFromEnv: %v", err)
	}
	if len(cfg.DCR.ApprovedRedirects) != 2 {
		t.Fatalf("expected 2 approved redirects, got %d", len(cfg.DCR.ApprovedRedirects))
	}
	if cfg.DCR.ApprovedRedirects[0] != "https://a.example.com/cb" {
		t.Errorf("first redirect: got %q", cfg.DCR.ApprovedRedirects[0])
	}
}

func TestValidateLogLevel(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Observability.Logging.Level = "trace"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for unsupported log level")
	}
	if !strings.Contains(err.Error(), "logging.level") {
		t.Errorf("error should mention logging.level: %v", err)
	}
}

func TestValidateLogFormat(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Observability.Logging.Format = "xml"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for unsupported log format")
	}
	if !strings.Contains(err.Error(), "logging.format") {
		t.Errorf("error should mention logging.format: %v", err)
	}
}

func TestValidateSameSite(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Session.SameSite = "invalid"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for unsupported same_site")
	}
	if !strings.Contains(err.Error(), "session.same_site") {
		t.Errorf("error should mention session.same_site: %v", err)
	}
}

func TestValidateTracingSampleRate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Observability.Tracing.SampleRate = 1.5
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for sample_rate > 1.0")
	}
	if !strings.Contains(err.Error(), "sample_rate") {
		t.Errorf("error should mention sample_rate: %v", err)
	}

	cfg.Observability.Tracing.SampleRate = -0.1
	err = cfg.Validate()
	if err == nil {
		t.Fatal("expected error for negative sample_rate")
	}
}

func TestValidate_DataEncryption_AESMaster_MissingKey_Fails(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DataEncryption.Driver = "aes_master"
	cfg.DataEncryption.AESMaster.KeyEnv = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing key_env")
	}
	if !strings.Contains(err.Error(), "data_encryption.aes_master.key_env") {
		t.Errorf("error should mention key_env: %v", err)
	}
}

func TestValidate_DataEncryption_AESMaster_ShortKey_Fails(t *testing.T) {
	// Set a key env var with wrong length (31 bytes = 62 hex chars instead of 64).
	t.Setenv("TEST_SHORT_KEY", "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbcc")
	cfg := DefaultConfig()
	cfg.DataEncryption.Driver = "aes_master"
	cfg.DataEncryption.AESMaster.KeyEnv = "TEST_SHORT_KEY"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for short key")
	}
	if !strings.Contains(err.Error(), "64 hex chars") {
		t.Errorf("error should mention 64 hex chars: %v", err)
	}
}

func TestValidate_DataEncryption_AESMaster_OldKeySameAsNew_Fails(t *testing.T) {
	sameKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	t.Setenv("TEST_KEY", sameKey)
	t.Setenv("TEST_OLD_KEY", sameKey)
	cfg := DefaultConfig()
	cfg.DataEncryption.Driver = "aes_master"
	cfg.DataEncryption.AESMaster.KeyEnv = "TEST_KEY"
	cfg.DataEncryption.AESMaster.OldKeyEnv = "TEST_OLD_KEY"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error when old_key_env equals key_env")
	}
	if !strings.Contains(err.Error(), "old_key_env must be different") {
		t.Errorf("error should mention old_key_env difference: %v", err)
	}
}

func TestValidate_DataEncryption_AESMaster_OldKeyValid(t *testing.T) {
	t.Setenv("TEST_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	t.Setenv("TEST_OLD_KEY", "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
	cfg := DefaultConfig()
	cfg.DataEncryption.Driver = "aes_master"
	cfg.DataEncryption.AESMaster.KeyEnv = "TEST_KEY"
	cfg.DataEncryption.AESMaster.OldKeyEnv = "TEST_OLD_KEY"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid old_key_env should pass: %v", err)
	}
}

func TestValidate_DataEncryption_VaultTransit_MissingAddress_Fails(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DataEncryption.Driver = "vault_transit_encrypt"
	cfg.DataEncryption.VaultTransitEncrypt.Address = ""
	cfg.DataEncryption.VaultTransitEncrypt.KeyName = "test-key"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing address")
	}
	if !strings.Contains(err.Error(), "address") {
		t.Errorf("error should mention address: %v", err)
	}
}

func TestValidate_OIDCEnabled_MissingIssuer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OIDC.Enabled = true
	cfg.OIDC.ClientID = "my-client"
	cfg.OIDC.ClientSecret = "my-secret"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for OIDC enabled with missing issuer")
	}
	if !strings.Contains(err.Error(), "oidc.issuer") {
		t.Errorf("error should mention oidc.issuer: %v", err)
	}
}

func TestValidate_OIDCEnabled_MissingClientID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OIDC.Enabled = true
	cfg.OIDC.Issuer = "https://accounts.google.com"
	cfg.OIDC.ClientSecret = "my-secret"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for OIDC enabled with missing client_id")
	}
	if !strings.Contains(err.Error(), "oidc.client_id") {
		t.Errorf("error should mention oidc.client_id: %v", err)
	}
}

func TestValidate_OIDCEnabled_MissingClientSecret(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OIDC.Enabled = true
	cfg.OIDC.Issuer = "https://accounts.google.com"
	cfg.OIDC.ClientID = "my-client"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for OIDC enabled with missing client_secret")
	}
	// Structural check: error must mention both secret fields so the operator
	// knows either client_secret or client_secret_ref satisfies the requirement.
	if !strings.Contains(err.Error(), "client_secret") {
		t.Errorf("error should mention client_secret: %v", err)
	}
	if !strings.Contains(err.Error(), "client_secret_ref") {
		t.Errorf("error should mention client_secret_ref: %v", err)
	}
}

func TestValidate_OIDCEnabled_BothSecretsRejected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OIDC.Enabled = true
	cfg.OIDC.Issuer = "https://accounts.google.com"
	cfg.OIDC.ClientID = "my-client"
	cfg.OIDC.RedirectURI = "https://app.example.com/oidc/callback"
	// Both set → mutually exclusive, must be rejected rather than resolved by
	// precedence.
	cfg.OIDC.ClientSecret = "inline-value"
	cfg.OIDC.ClientSecretRef = "CONNECTOR_OIDC_SECRET"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error when both client_secret and client_secret_ref are set")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should state the fields are mutually exclusive: %v", err)
	}
}

func TestValidate_OIDCIssuerHTTPS(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OIDC.Enabled = true
	cfg.OIDC.Issuer = "http://accounts.google.com"
	cfg.OIDC.ClientID = "my-client"
	cfg.OIDC.ClientSecret = "my-secret"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for non-HTTPS OIDC issuer in production")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("error should mention HTTPS: %v", err)
	}
}

func TestValidate_OIDCIssuerHTTPLocalhostAllowed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OIDC.Enabled = true
	cfg.OIDC.Issuer = "http://localhost:8080"
	cfg.OIDC.ClientID = "my-client"
	cfg.OIDC.ClientSecret = "my-secret"
	cfg.OIDC.RedirectURI = "http://localhost:9000/oidc/callback"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("HTTP localhost OIDC issuer should be allowed for dev: %v", err)
	}
}

func TestValidate_OIDCDisabled_NoValidation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OIDC.Enabled = false
	// Leave all OIDC fields empty — should be fine when disabled.
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled OIDC should not trigger validation: %v", err)
	}
}

func TestEnvOverrideOIDC(t *testing.T) {
	t.Setenv("AUTHPLANE_OIDC_ENABLED", "true")
	t.Setenv("AUTHPLANE_OIDC_ISSUER", "https://idp.example.com")
	t.Setenv("AUTHPLANE_OIDC_CLIENT_ID", "test-client")
	t.Setenv("AUTHPLANE_OIDC_CLIENT_SECRET", "test-secret")
	t.Setenv("AUTHPLANE_OIDC_DISPLAY_NAME", "Test IdP")
	t.Setenv("AUTHPLANE_OIDC_SCOPES", "openid,email")
	cfg := DefaultConfig()
	if err := loadFromEnv(cfg); err != nil {
		t.Fatalf("loadFromEnv: %v", err)
	}
	if !cfg.OIDC.Enabled {
		t.Error("OIDC.Enabled should be true")
	}
	if cfg.OIDC.Issuer != "https://idp.example.com" {
		t.Errorf("OIDC.Issuer = %q", cfg.OIDC.Issuer)
	}
	if cfg.OIDC.ClientID != "test-client" {
		t.Errorf("OIDC.ClientID = %q", cfg.OIDC.ClientID)
	}
	if cfg.OIDC.ClientSecret != "test-secret" {
		t.Errorf("OIDC.ClientSecret = %q", cfg.OIDC.ClientSecret)
	}
	if cfg.OIDC.DisplayName != "Test IdP" {
		t.Errorf("OIDC.DisplayName = %q", cfg.OIDC.DisplayName)
	}
	if len(cfg.OIDC.Scopes) != 2 || cfg.OIDC.Scopes[0] != "openid" {
		t.Errorf("OIDC.Scopes = %v", cfg.OIDC.Scopes)
	}
}

// --- New OIDC config tests ---

func TestValidate_OIDCRedirectURIRequired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OIDC.Enabled = true
	cfg.OIDC.Issuer = "http://localhost:8080"
	cfg.OIDC.ClientID = "my-client"
	cfg.OIDC.ClientSecret = "my-secret"
	cfg.OIDC.RedirectURI = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing redirect_uri")
	}
	if !strings.Contains(err.Error(), "oidc.redirect_uri") {
		t.Errorf("error should mention oidc.redirect_uri: %v", err)
	}
}

func TestValidate_OIDCRedirectURIHTTPS(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Issuer = "https://auth.example.com"
	cfg.Session.Secret = "test-secret-32-bytes-long-enough"
	cfg.Session.Secure = true
	cfg.Admin.APIKey = "test-admin-key-strong-enough"
	cfg.OIDC.Enabled = true
	cfg.OIDC.Issuer = "https://accounts.google.com"
	cfg.OIDC.ClientID = "my-client"
	cfg.OIDC.ClientSecret = "my-secret"
	cfg.OIDC.RedirectURI = "http://auth.example.com/oidc/callback"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for non-HTTPS redirect_uri in production")
	}
	if !strings.Contains(err.Error(), "oidc.redirect_uri") {
		t.Errorf("error should mention oidc.redirect_uri: %v", err)
	}
}

func TestValidate_ConnectorIDValid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OIDC.Enabled = true
	cfg.OIDC.Issuer = "http://localhost:5556"
	cfg.OIDC.ClientID = "my-client"
	cfg.OIDC.ClientSecret = "my-secret"
	cfg.OIDC.RedirectURI = "http://localhost:9000/oidc/callback"
	cfg.OIDC.ConnectorID = "github-connector"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid connector_id should pass: %v", err)
	}
}

func TestValidate_ConnectorIDInvalid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OIDC.Enabled = true
	cfg.OIDC.Issuer = "http://localhost:5556"
	cfg.OIDC.ClientID = "my-client"
	cfg.OIDC.ClientSecret = "my-secret"
	cfg.OIDC.RedirectURI = "http://localhost:9000/oidc/callback"
	cfg.OIDC.ConnectorID = "invalid connector!@#"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for invalid connector_id")
	}
	if !strings.Contains(err.Error(), "oidc.connector_id") {
		t.Errorf("error should mention oidc.connector_id: %v", err)
	}
}

func TestDefaultConfig_OIDCDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.OIDC.ShowLocalLogin {
		t.Error("ShowLocalLogin should default to true")
	}
	if !cfg.OIDC.IncludeGroupsScope {
		t.Error("IncludeGroupsScope should default to true")
	}
}

func TestEnvOverrideOIDCNewFields(t *testing.T) {
	t.Setenv("AUTHPLANE_OIDC_REDIRECT_URI", "https://auth.example.com/oidc/callback")
	t.Setenv("AUTHPLANE_OIDC_SHOW_LOCAL_LOGIN", "false")
	t.Setenv("AUTHPLANE_OIDC_INCLUDE_GROUPS_SCOPE", "false")
	t.Setenv("AUTHPLANE_OIDC_CONNECTOR_ID", "github")
	cfg := DefaultConfig()
	if err := loadFromEnv(cfg); err != nil {
		t.Fatalf("loadFromEnv: %v", err)
	}
	if cfg.OIDC.RedirectURI != "https://auth.example.com/oidc/callback" {
		t.Errorf("OIDC.RedirectURI = %q", cfg.OIDC.RedirectURI)
	}
	if cfg.OIDC.ShowLocalLogin {
		t.Error("ShowLocalLogin should be false after env override")
	}
	if cfg.OIDC.IncludeGroupsScope {
		t.Error("IncludeGroupsScope should be false after env override")
	}
	if cfg.OIDC.ConnectorID != "github" {
		t.Errorf("OIDC.ConnectorID = %q", cfg.OIDC.ConnectorID)
	}
}

// --- Vault Transit config tests ---

func TestValidate_VaultTransit_RequiresAddress(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Signing.KeyStore = "vault_transit"
	cfg.Signing.VaultTransit.Address = ""
	cfg.Signing.VaultTransit.Token = "test-token"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing vault address")
	}
	if !strings.Contains(err.Error(), "vault_transit.address") {
		t.Errorf("error should mention vault_transit.address: %v", err)
	}
}

func TestValidate_VaultTransit_RequiresAuth(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Signing.KeyStore = "vault_transit"
	cfg.Signing.VaultTransit.Address = "http://localhost:8200"
	cfg.Signing.VaultTransit.Token = ""
	cfg.Signing.VaultTransit.AppRole.RoleID = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing auth")
	}
	if !strings.Contains(err.Error(), "token or approle") {
		t.Errorf("error should mention token or approle: %v", err)
	}
}

func TestValidate_VaultTransit_MutuallyExclusiveAuth(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Signing.KeyStore = "vault_transit"
	cfg.Signing.VaultTransit.Address = "http://localhost:8200"
	cfg.Signing.VaultTransit.Token = "test-token"
	cfg.Signing.VaultTransit.AppRole.RoleID = "role-id"
	cfg.Signing.VaultTransit.AppRole.SecretID = "secret-id"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for mutually exclusive auth")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should mention mutually exclusive: %v", err)
	}
}

func TestValidate_VaultTransit_AppRoleRequiresSecretID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Signing.KeyStore = "vault_transit"
	cfg.Signing.VaultTransit.Address = "http://localhost:8200"
	cfg.Signing.VaultTransit.AppRole.RoleID = "role-id"
	cfg.Signing.VaultTransit.AppRole.SecretID = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing approle secret_id")
	}
	if !strings.Contains(err.Error(), "secret_id") {
		t.Errorf("error should mention secret_id: %v", err)
	}
}

func TestValidate_VaultTransit_ValidToken(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Signing.KeyStore = "vault_transit"
	cfg.Signing.VaultTransit.Address = "http://localhost:8200"
	cfg.Signing.VaultTransit.Token = "test-token"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid vault_transit with token should pass: %v", err)
	}
}

func TestValidate_VaultTransit_ValidAppRole(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Signing.KeyStore = "vault_transit"
	cfg.Signing.VaultTransit.Address = "http://localhost:8200"
	cfg.Signing.VaultTransit.AppRole.RoleID = "role-id"
	cfg.Signing.VaultTransit.AppRole.SecretID = "secret-id"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid vault_transit with approle should pass: %v", err)
	}
}

func TestValidate_VaultTransit_KeyPathNotRequired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Signing.KeyStore = "vault_transit"
	cfg.Signing.KeyPath = "" // Should not be required for vault_transit
	cfg.Signing.VaultTransit.Address = "http://localhost:8200"
	cfg.Signing.VaultTransit.Token = "test-token"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("vault_transit should not require key_path: %v", err)
	}
}

func TestValidate_InvalidKeyStore(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Signing.KeyStore = "invalid"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for invalid key_store")
	}
	if !strings.Contains(err.Error(), "key_store") {
		t.Errorf("error should mention key_store: %v", err)
	}
}

func TestEnvOverrideVaultTransit(t *testing.T) {
	t.Setenv("AUTHPLANE_SIGNING_KEY_STORE", "vault_transit")
	t.Setenv("AUTHPLANE_VAULT_ADDR", "http://vault.local:8200")
	t.Setenv("AUTHPLANE_VAULT_TOKEN", "my-vault-token")
	t.Setenv("AUTHPLANE_VAULT_TRANSIT_MOUNT", "custom-transit")
	t.Setenv("AUTHPLANE_VAULT_TRANSIT_KEY_NAME", "custom-key")
	t.Setenv("AUTHPLANE_VAULT_TIMEOUT", "30s")
	cfg := DefaultConfig()
	if err := loadFromEnv(cfg); err != nil {
		t.Fatalf("loadFromEnv: %v", err)
	}
	if cfg.Signing.KeyStore != "vault_transit" {
		t.Errorf("KeyStore = %q, want vault_transit", cfg.Signing.KeyStore)
	}
	if cfg.Signing.VaultTransit.Address != "http://vault.local:8200" {
		t.Errorf("Address = %q", cfg.Signing.VaultTransit.Address)
	}
	if cfg.Signing.VaultTransit.Token != "my-vault-token" {
		t.Errorf("Token = %q", cfg.Signing.VaultTransit.Token)
	}
	if cfg.Signing.VaultTransit.Mount != "custom-transit" {
		t.Errorf("Mount = %q", cfg.Signing.VaultTransit.Mount)
	}
	if cfg.Signing.VaultTransit.KeyName != "custom-key" {
		t.Errorf("KeyName = %q", cfg.Signing.VaultTransit.KeyName)
	}
	if cfg.Signing.VaultTransit.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", cfg.Signing.VaultTransit.Timeout)
	}
}

func TestEnvOverrideVaultAppRole(t *testing.T) {
	t.Setenv("AUTHPLANE_VAULT_APPROLE_ROLE_ID", "my-role")
	t.Setenv("AUTHPLANE_VAULT_APPROLE_SECRET_ID", "my-secret")
	t.Setenv("AUTHPLANE_VAULT_APPROLE_MOUNT", "custom-approle")
	cfg := DefaultConfig()
	if err := loadFromEnv(cfg); err != nil {
		t.Fatalf("loadFromEnv: %v", err)
	}
	if cfg.Signing.VaultTransit.AppRole.RoleID != "my-role" {
		t.Errorf("RoleID = %q", cfg.Signing.VaultTransit.AppRole.RoleID)
	}
	if cfg.Signing.VaultTransit.AppRole.SecretID != "my-secret" {
		t.Errorf("SecretID = %q", cfg.Signing.VaultTransit.AppRole.SecretID)
	}
	if cfg.Signing.VaultTransit.AppRole.Mount != "custom-approle" {
		t.Errorf("Mount = %q", cfg.Signing.VaultTransit.AppRole.Mount)
	}
}

func TestDefaultConfig_VaultTransitDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Signing.KeyStore != "keyfile" {
		t.Errorf("KeyStore default = %q, want keyfile", cfg.Signing.KeyStore)
	}
	if cfg.Signing.VaultTransit.Mount != "transit" {
		t.Errorf("Mount default = %q, want transit", cfg.Signing.VaultTransit.Mount)
	}
	if cfg.Signing.VaultTransit.KeyName != "authserver-signing" {
		t.Errorf("KeyName default = %q, want authserver-signing", cfg.Signing.VaultTransit.KeyName)
	}
	if cfg.Signing.VaultTransit.Timeout != 10*time.Second {
		t.Errorf("Timeout default = %v, want 10s", cfg.Signing.VaultTransit.Timeout)
	}
}

// --- OAuth config tests ---

func TestDefaultConfig_OAuthRequireScope(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.OAuth.RequireScope {
		t.Error("OAuth.RequireScope should default to true (strict RFC 6749 §3.3)")
	}
}

func TestEnvOverrideOAuthRequireScope(t *testing.T) {
	t.Setenv("AUTHPLANE_OAUTH_REQUIRE_SCOPE", "false")
	cfg := DefaultConfig()
	if err := loadFromEnv(cfg); err != nil {
		t.Fatalf("loadFromEnv: %v", err)
	}
	if cfg.OAuth.RequireScope {
		t.Error("OAuth.RequireScope should be false after env override")
	}
}

func TestDefaultConfig_OAuthStateMaxAge(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.OAuth.StateMaxAge != 10*time.Minute {
		t.Errorf("OAuth.StateMaxAge default = %v, want 10m", cfg.OAuth.StateMaxAge)
	}
}

func TestEnvOverrideOAuthStateMaxAge(t *testing.T) {
	t.Setenv("AUTHPLANE_OAUTH_STATE_MAX_AGE", "2m")
	cfg := DefaultConfig()
	if err := loadFromEnv(cfg); err != nil {
		t.Fatalf("loadFromEnv: %v", err)
	}
	if cfg.OAuth.StateMaxAge != 2*time.Minute {
		t.Errorf("OAuth.StateMaxAge after env = %v, want 2m", cfg.OAuth.StateMaxAge)
	}
}

func TestIsLocalhostIssuer(t *testing.T) {
	tests := []struct {
		issuer string
		want   bool
	}{
		{"http://localhost:9000", true},
		{"https://localhost", true},
		{"http://127.0.0.1:9000", true},
		{"http://[::1]:9000", true},
		{"https://auth.example.com", false},
		{"http://localhost.evil.com", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.issuer, func(t *testing.T) {
			got := isLocalhostIssuer(tt.issuer)
			if got != tt.want {
				t.Errorf("isLocalhostIssuer(%q) = %v, want %v", tt.issuer, got, tt.want)
			}
		})
	}
}

// --- PostgreSQL signing key store config tests ---

func TestValidate_PostgresKey_RequiresPostgresStorage(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Signing.KeyStore = "postgres_key"
	cfg.Storage.Driver = "sqlite" // Wrong driver
	cfg.DataEncryption.Driver = "aes_master"
	cfg.DataEncryption.AESMaster.KeyEnv = "TEST_KEY"
	t.Setenv("TEST_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for postgres_key with sqlite storage")
	}
	if !strings.Contains(err.Error(), "storage.driver=postgres") {
		t.Errorf("error should mention storage.driver=postgres: %v", err)
	}
}

func TestValidate_PostgresKey_RequiresEncryption(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Signing.KeyStore = "postgres_key"
	cfg.Storage.Driver = "postgres"
	cfg.Storage.Postgres.DSN = "postgres://localhost/test"
	cfg.DataEncryption.Driver = "" // No encryption configured
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for postgres_key without data_encryption")
	}
	if !strings.Contains(err.Error(), "data_encryption") {
		t.Errorf("error should mention data_encryption: %v", err)
	}
}

func TestValidate_PostgresKey_Valid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Signing.KeyStore = "postgres_key"
	cfg.Storage.Driver = "postgres"
	cfg.Storage.Postgres.DSN = "postgres://localhost/test"
	cfg.DataEncryption.Driver = "aes_master"
	cfg.DataEncryption.AESMaster.KeyEnv = "TEST_KEY"
	t.Setenv("TEST_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid postgres_key config should pass: %v", err)
	}
}

// --- Upstream-connection redirect_base_url validation tests ---

func connectTestConfig(t *testing.T) *Config {
	t.Helper()
	cfg := DefaultConfig()
	cfg.DataEncryption.Driver = "aes_master"
	cfg.DataEncryption.AESMaster.KeyEnv = "TEST_KEY"
	t.Setenv("TEST_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	cfg.Connect.StateSecret = "01234567890123456789012345678901" // 32 chars
	return cfg
}

func TestValidate_Connect_RedirectBaseURL_HTTPS_Valid(t *testing.T) {
	cfg := connectTestConfig(t)
	cfg.Connect.RedirectBaseURL = "https://auth.example.com"
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("HTTPS redirect_base_url should be valid: %v", err)
	}
}

func TestValidate_Connect_RedirectBaseURL_LocalhostHTTP_Valid(t *testing.T) {
	cfg := connectTestConfig(t)
	cfg.Connect.RedirectBaseURL = "http://localhost:9000"
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("localhost HTTP redirect_base_url should be valid: %v", err)
	}
}

func TestValidate_Connect_RedirectBaseURL_Empty_Valid(t *testing.T) {
	cfg := connectTestConfig(t)
	cfg.Connect.RedirectBaseURL = ""
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("empty redirect_base_url should be valid: %v", err)
	}
}

func TestValidate_Connect_RedirectBaseURL_PlainHTTP_Rejected(t *testing.T) {
	cfg := connectTestConfig(t)
	cfg.Connect.RedirectBaseURL = "http://auth.example.com"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("plain HTTP redirect_base_url should be rejected")
	}
	if !strings.Contains(err.Error(), "redirect_base_url") {
		t.Errorf("error should mention redirect_base_url: %v", err)
	}
}

func TestValidate_Connect_RedirectBaseURL_Malformed_Rejected(t *testing.T) {
	cfg := connectTestConfig(t)
	cfg.Connect.RedirectBaseURL = "not-a-url"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("malformed redirect_base_url should be rejected")
	}
	if !strings.Contains(err.Error(), "redirect_base_url") {
		t.Errorf("error should mention redirect_base_url: %v", err)
	}
}

// --- Weak secret blocklist tests ---

func TestValidate_WeakSessionSecret_Rejected(t *testing.T) {
	for _, weak := range []string{"dev-secret-change-me", "changeme", "secret", "password", "admin", "test"} {
		t.Run(weak, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Session.Secret = weak
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected error for weak session secret %q", weak)
			}
			if !strings.Contains(err.Error(), "weak/default") {
				t.Errorf("error should mention weak/default: %v", err)
			}
		})
	}
}

func TestValidate_WeakAdminAPIKey_Rejected(t *testing.T) {
	for _, weak := range []string{"dev-admin-key", "changeme", "secret", "password", "admin", "test"} {
		t.Run(weak, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Admin.Enabled = true
			cfg.Admin.APIKey = weak
			err := cfg.ValidateAdminAPIKey()
			if err == nil {
				t.Fatalf("expected error for weak admin API key %q", weak)
			}
			if !strings.Contains(err.Error(), "weak/default") {
				t.Errorf("error should mention weak/default: %v", err)
			}
		})
	}
}

func TestValidate_ShortSessionSecret_RejectedInProduction(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Issuer = "https://auth.example.com"
	cfg.Session.Secret = "short" // Only 5 chars, not a known weak value but too short
	cfg.Session.Secure = true
	cfg.Admin.APIKey = "test-admin-key-strong-enough"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for short session secret in production")
	}
	if !strings.Contains(err.Error(), "at least 16 characters") {
		t.Errorf("error should mention minimum length: %v", err)
	}
}

func TestValidate_ShortAdminAPIKey_RejectedInProduction(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Issuer = "https://auth.example.com"
	cfg.Session.Secret = "test-secret-long-enough"
	cfg.Session.Secure = true
	cfg.Admin.Enabled = true
	cfg.Admin.APIKey = "short" // Only 5 chars
	err := cfg.ValidateAdminAPIKey()
	if err == nil {
		t.Fatal("expected error for short admin API key in production")
	}
	if !strings.Contains(err.Error(), "at least 16 characters") {
		t.Errorf("error should mention minimum length: %v", err)
	}
}

func TestValidate_StrongSecrets_Accepted(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Issuer = "https://auth.example.com"
	cfg.Session.Secret = "a-very-strong-production-session-secret"
	cfg.Session.Secure = true
	cfg.Admin.APIKey = "a-very-strong-production-admin-key"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("strong secrets should pass validation: %v", err)
	}
}

// --- : unified resources: + broker_providers: YAML shape ---

func writeTempYAML(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp yaml: %v", err)
	}
	return p
}

// strongConfigPrelude returns a YAML head with the secrets required by
// validation in production-ish issuers, used by the legacy-key tests below.
func strongConfigPrelude() string {
	return `server:
  issuer: "https://auth.example.com"
session:
  secret: "a-very-strong-session-secret-for-tests"
  secure: true
admin:
  api_key: "a-very-strong-admin-key-for-tests"
`
}

// TestConfig_LoadResources_RoundTripsUnifiedShape parses the new resources:
// shape end-to-end and asserts the unified-shape fields land on the Go struct.
func TestConfig_LoadResources_RoundTripsUnifiedShape(t *testing.T) {
	path := writeTempYAML(t, strongConfigPrelude()+`broker_providers:
  - slug: github
    display_name: GitHub
    protocol: oauth
    config_data:
      client_id: "Iv1.test"
      client_secret_ref: "CONNECTOR_GITHUB_SECRET"

resources:
  - slug: tasks-mcp
    uri: "https://tasks-mcp.example.com"
    backend_kind: mint
    display_name: Tasks MCP
    scopes:
      - name: tasks:summarize
        description: Summarize tasks
    policy:
      exchange:
        allowed_client_ids: ["notes-agent"]
  - slug: github-repo
    uri: "https://api.github.com"
    backend_kind: broker
    broker_provider_slug: github
    display_name: GitHub Repository API
    scopes:
      - name: repo
        upstream: repo
        description: Read/write repo
    policy:
      connect:
        allowed_return_urls: ["https://app.example.com/oauth/return"]
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Resources) != 2 {
		t.Fatalf("Resources len: got %d, want 2", len(cfg.Resources))
	}

	mint := cfg.Resources[0]
	if mint.Slug != "tasks-mcp" || mint.BackendKind != "mint" {
		t.Errorf("mint resource: got slug=%q backend=%q", mint.Slug, mint.BackendKind)
	}
	if got := mint.Policy.Exchange.AllowedClientIDs; len(got) != 1 || got[0] != "notes-agent" {
		t.Errorf("mint policy.exchange.allowed_client_ids: got %v", got)
	}
	if mint.BrokerProviderSlug != "" {
		t.Errorf("mint broker_provider_slug should be empty, got %q", mint.BrokerProviderSlug)
	}

	broker := cfg.Resources[1]
	if broker.Slug != "github-repo" || broker.BackendKind != "broker" {
		t.Errorf("broker resource: got slug=%q backend=%q", broker.Slug, broker.BackendKind)
	}
	if broker.BrokerProviderSlug != "github" {
		t.Errorf("broker_provider_slug: got %q", broker.BrokerProviderSlug)
	}
	if got := broker.Scopes[0].Upstream; got != "repo" {
		t.Errorf("scope[0].upstream: got %q", got)
	}
	if got := broker.Policy.Connect.AllowedReturnURLs; len(got) != 1 || got[0] != "https://app.example.com/oauth/return" {
		t.Errorf("connect.allowed_return_urls: got %v", got)
	}
}

// TestConfig_LoadBrokerProviders_RoundTripsConfigData asserts ConfigData
// preserves nested map shapes (the brokerproto adapter validates JSON shape
// at first vend; the seed loop is intentionally pass-through).
func TestConfig_LoadBrokerProviders_RoundTripsConfigData(t *testing.T) {
	path := writeTempYAML(t, strongConfigPrelude()+`broker_providers:
  - slug: google
    display_name: Google
    protocol: oauth
    config_data:
      client_id: "google-cid"
      authorize_url: "https://accounts.google.com/o/oauth2/v2/auth"
      token_url: "https://oauth2.googleapis.com/token"
      extra_auth_params:
        access_type: offline
        prompt: consent
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.BrokerProviders) != 1 {
		t.Fatalf("BrokerProviders len: got %d", len(cfg.BrokerProviders))
	}
	bp := cfg.BrokerProviders[0]
	if bp.Slug != "google" || bp.Protocol != "oauth" {
		t.Errorf("provider meta: got slug=%q protocol=%q", bp.Slug, bp.Protocol)
	}
	extra, ok := bp.ConfigData["extra_auth_params"].(map[string]interface{})
	if !ok {
		t.Fatalf("extra_auth_params: got %T", bp.ConfigData["extra_auth_params"])
	}
	if extra["access_type"] != "offline" || extra["prompt"] != "consent" {
		t.Errorf("extra_auth_params: got %v", extra)
	}
}

func TestConfig_LegacyKey_resource_servers_RejectedWithMigrationHint(t *testing.T) {
	path := writeTempYAML(t, strongConfigPrelude()+`resource_servers:
  - name: calc
    uri: "http://example.com"
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for legacy key 'resource_servers'")
	}
	msg := err.Error()
	if !strings.Contains(msg, "resource_servers") || !strings.Contains(msg, "v0.1.0-rc1") {
		t.Errorf("error should mention legacy key + removal version, got: %v", err)
	}
	if !strings.Contains(msg, "resources:") {
		t.Errorf("error should mention 'resources:' replacement, got: %v", err)
	}
}

func TestConfig_LegacyKey_vault_connectors_Rejected(t *testing.T) {
	path := writeTempYAML(t, strongConfigPrelude()+`vault_connectors:
  - service: github
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "vault_connectors") {
		t.Fatalf("expected vault_connectors rejection, got: %v", err)
	}
	if !strings.Contains(err.Error(), "broker_providers") {
		t.Errorf("error should mention 'broker_providers' replacement, got: %v", err)
	}
}

func TestConfig_LegacyKey_vault_connect_Rejected(t *testing.T) {
	path := writeTempYAML(t, strongConfigPrelude()+`vault_connect:
  state_secret: "01234567890123456789012345678901"
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "vault_connect") {
		t.Fatalf("expected vault_connect rejection, got: %v", err)
	}
	if !strings.Contains(err.Error(), "connect:") {
		t.Errorf("error should mention 'connect:' replacement, got: %v", err)
	}
}

func TestConfig_LegacyKey_cross_client_allowlist_Rejected(t *testing.T) {
	path := writeTempYAML(t, strongConfigPrelude()+`token_exchange:
  enabled: true
  cross_client_allowlist:
    - subject_client_id: a
      actor_client_id: b
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "cross_client_allowlist") {
		t.Fatalf("expected cross_client_allowlist rejection, got: %v", err)
	}
	if !strings.Contains(err.Error(), "policy.exchange.allowed_client_ids") {
		t.Errorf("error should mention per-resource policy replacement, got: %v", err)
	}
}

func TestLoadConnectFromEnv_NewPrefix(t *testing.T) {
	t.Setenv("AUTHPLANE_CONNECT_STATE_SECRET", "abc")
	cfg := DefaultConfig()
	if err := loadFromEnv(cfg); err != nil {
		t.Fatalf("loadFromEnv: %v", err)
	}
	if cfg.Connect.StateSecret != "abc" {
		t.Errorf("AUTHPLANE_CONNECT_STATE_SECRET should populate cfg.Connect.StateSecret, got %q", cfg.Connect.StateSecret)
	}
}

func TestLoadConnectFromEnv_LegacyVarIgnored(t *testing.T) {
	t.Setenv("AUTHPLANE_VAULT_CONNECT_STATE_SECRET", "ignored-legacy")
	cfg := DefaultConfig()
	if err := loadFromEnv(cfg); err != nil {
		t.Fatalf("loadFromEnv: %v", err)
	}
	if cfg.Connect.StateSecret == "ignored-legacy" {
		t.Errorf("legacy AUTHPLANE_VAULT_CONNECT_STATE_SECRET must NOT populate cfg.Connect.StateSecret")
	}
}

func TestLoadBrokerProviderFromEnv_PopulatesBrokerProvidersList(t *testing.T) {
	t.Setenv("AUTHPLANE_BROKER_PROVIDER_SLUG", "github")
	t.Setenv("AUTHPLANE_BROKER_PROVIDER_DISPLAY_NAME", "GitHub")
	t.Setenv("AUTHPLANE_BROKER_PROVIDER_CLIENT_ID", "Iv1.test")
	t.Setenv("AUTHPLANE_BROKER_PROVIDER_CLIENT_SECRET_REF", "CONNECTOR_GITHUB_SECRET")
	t.Setenv("AUTHPLANE_BROKER_PROVIDER_AUTHORIZE_URL", "https://github.com/login/oauth/authorize")
	t.Setenv("AUTHPLANE_BROKER_PROVIDER_TOKEN_URL", "https://github.com/login/oauth/access_token")

	cfg := DefaultConfig()
	if err := loadFromEnv(cfg); err != nil {
		t.Fatalf("loadFromEnv: %v", err)
	}
	if len(cfg.BrokerProviders) != 1 {
		t.Fatalf("BrokerProviders len: got %d, want 1", len(cfg.BrokerProviders))
	}
	bp := cfg.BrokerProviders[0]
	if bp.Slug != "github" || bp.DisplayName != "GitHub" || bp.Protocol != "oauth" {
		t.Errorf("provider meta: got %+v", bp)
	}
	if bp.ConfigData["client_secret_ref"] != "CONNECTOR_GITHUB_SECRET" {
		t.Errorf("client_secret_ref: got %v", bp.ConfigData["client_secret_ref"])
	}
	if bp.ConfigData["client_id"] != "Iv1.test" {
		t.Errorf("client_id: got %v", bp.ConfigData["client_id"])
	}
}

func TestLoadResourcesFromEnv_DerivesSlugFromURIHost(t *testing.T) {
	cases := []struct {
		uri  string
		want string
	}{
		{"https://Tasks-MCP.Example.COM/", "tasks-mcp-example-com"},
		{"http://localhost:3000/mcp", "localhost"},
		{"http://192.168.1.1/mcp", "192-168-1-1"},
	}
	for _, c := range cases {
		t.Run(c.uri, func(t *testing.T) {
			t.Setenv("AUTHPLANE_RESOURCE_URI", c.uri)
			cfg := DefaultConfig()
			if err := loadFromEnv(cfg); err != nil {
				t.Fatalf("loadFromEnv: %v", err)
			}
			if len(cfg.Resources) != 1 {
				t.Fatalf("Resources len: got %d", len(cfg.Resources))
			}
			if got := cfg.Resources[0].Slug; got != c.want {
				t.Errorf("slug for %q: got %q, want %q", c.uri, got, c.want)
			}
			if cfg.Resources[0].BackendKind != "mint" {
				t.Errorf("backend_kind: got %q, want mint", cfg.Resources[0].BackendKind)
			}
		})
	}
}

func TestLoadResourcesFromEnv_PathologicalHostFails(t *testing.T) {
	// Hostname `--` reduces to empty after trim → structured error.
	t.Setenv("AUTHPLANE_RESOURCE_URI", "https://--/")
	cfg := DefaultConfig()
	err := loadFromEnv(cfg)
	if err == nil {
		t.Fatal("expected error for pathological URI host")
	}
	if !strings.Contains(err.Error(), "AUTHPLANE_RESOURCE_URI") {
		t.Errorf("error should mention env var name, got: %v", err)
	}
}

func TestHasYAMLKey_TableDriven(t *testing.T) {
	raw := map[string]interface{}{
		"top": "x",
		"nested": map[string]interface{}{
			"inner": "y",
			"deeper": map[string]interface{}{
				"leaf": "z",
			},
		},
	}
	cases := []struct {
		path string
		want bool
	}{
		{"top", true},
		{"nested.inner", true},
		{"nested.deeper.leaf", true},
		{"missing", false},
		{"nested.missing", false},
		{"top.notamap", false}, // non-map intermediate stops the walk
	}
	for _, c := range cases {
		if got := hasYAMLKey(raw, c.path); got != c.want {
			t.Errorf("hasYAMLKey(%q): got %v, want %v", c.path, got, c.want)
		}
	}
}

func TestValidateAdminAPIKey_ValidCases(t *testing.T) {
	// Strong key in production → ok.
	prod := DefaultConfig()
	prod.Server.Issuer = "https://auth.example.com"
	prod.Admin.Enabled = true
	prod.Admin.APIKey = "a-very-strong-production-admin-key"
	if err := prod.ValidateAdminAPIKey(); err != nil {
		t.Errorf("strong admin api_key in production should pass, got: %v", err)
	}

	// Localhost issuer with no key → ok (dev).
	dev := DefaultConfig()
	dev.Server.Issuer = "http://localhost:8080"
	dev.Admin.Enabled = true
	dev.Admin.APIKey = ""
	if err := dev.ValidateAdminAPIKey(); err != nil {
		t.Errorf("empty admin api_key on localhost should pass, got: %v", err)
	}
}

// TestValidate_OmitsAdminAPIKey confirms the shared Validate() no longer
// enforces the admin api_key policy — that is the OSS binary's job via
// ValidateAdminAPIKey, so a deployment fronted by external auth can reuse
// Validate() without setting an api_key.
func TestValidate_OmitsAdminAPIKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Issuer = "https://auth.example.com"
	cfg.Session.Secret = "test-secret-long-enough"
	cfg.Session.Secure = true
	cfg.Admin.Enabled = true
	cfg.Admin.APIKey = ""
	if err := cfg.Validate(); err != nil && strings.Contains(err.Error(), "admin.api_key") {
		t.Errorf("Validate() must not enforce admin.api_key: %v", err)
	}
}

// A unit-less AUTHPLANE_OAUTH_STATE_MAX_AGE (e.g. the seconds form "120" that
// time.ParseDuration rejects) must be a boot failure, not a silent revert to
// the 10m default — otherwise the security knob appears to tighten the state
// replay window and doesn't.
func TestEnvOAuthStateMaxAge_UnparseableIsBootError(t *testing.T) {
	t.Setenv("AUTHPLANE_OAUTH_STATE_MAX_AGE", "120")
	cfg := DefaultConfig()
	if err := loadFromEnv(cfg); err == nil {
		t.Fatal("expected a boot error for a unit-less duration, got nil (silent revert)")
	} else if !strings.Contains(err.Error(), "AUTHPLANE_OAUTH_STATE_MAX_AGE") {
		t.Errorf("error should name the offending env var: %v", err)
	}
}

// A valid duration still loads.
func TestEnvOAuthStateMaxAge_ValidDurationLoads(t *testing.T) {
	t.Setenv("AUTHPLANE_OAUTH_STATE_MAX_AGE", "2m")
	cfg := DefaultConfig()
	if err := loadFromEnv(cfg); err != nil {
		t.Fatalf("loadFromEnv: %v", err)
	}
	if cfg.OAuth.StateMaxAge != 2*time.Minute {
		t.Errorf("StateMaxAge = %v, want 2m", cfg.OAuth.StateMaxAge)
	}
}

// An explicit zero/negative (from YAML, which the strict env parse doesn't see)
// is caught by Validate rather than silently clamped back to the default.
func TestValidateRejectsNonPositiveOAuthStateMaxAge(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Minute} {
		cfg := DefaultConfig()
		cfg.OAuth.StateMaxAge = d
		err := cfg.Validate()
		if err == nil {
			t.Fatalf("StateMaxAge=%v: expected a validation error", d)
		}
		if !strings.Contains(err.Error(), "oauth.state_max_age") {
			t.Errorf("StateMaxAge=%v: error should mention oauth.state_max_age: %v", d, err)
		}
	}
}

// Sibling of the oauth.state_max_age hardening: a unit-less
// AUTHPLANE_SESSION_MAX_AGE (e.g. a bare seconds value like "28800") must be a
// boot error, not a silent revert to 24h. The middleware clamps a zero/negative
// MaxAge up to DefaultSessionMaxAge, so a lenient revert here would be invisible
// — an operator shortening the session for compliance would silently get 24h.
func TestEnvSessionMaxAge_UnparseableIsBootError(t *testing.T) {
	t.Setenv("AUTHPLANE_SESSION_MAX_AGE", "28800")
	cfg := DefaultConfig()
	if err := loadFromEnv(cfg); err == nil {
		t.Fatal("expected a boot error for a unit-less duration, got nil (silent revert)")
	} else if !strings.Contains(err.Error(), "AUTHPLANE_SESSION_MAX_AGE") {
		t.Errorf("error should name the offending env var: %v", err)
	}
}

func TestEnvSessionMaxAge_ValidDurationLoads(t *testing.T) {
	t.Setenv("AUTHPLANE_SESSION_MAX_AGE", "8h")
	cfg := DefaultConfig()
	if err := loadFromEnv(cfg); err != nil {
		t.Fatalf("loadFromEnv: %v", err)
	}
	if cfg.Session.MaxAge != 8*time.Hour {
		t.Errorf("Session.MaxAge = %v, want 8h", cfg.Session.MaxAge)
	}
}

// An explicit zero/negative session.max_age (from YAML, which the strict env
// parse doesn't see) is caught by Validate rather than silently clamped to 24h.
func TestValidateRejectsNonPositiveSessionMaxAge(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Hour} {
		cfg := DefaultConfig()
		cfg.Session.MaxAge = d
		err := cfg.Validate()
		if err == nil {
			t.Fatalf("Session.MaxAge=%v: expected a validation error", d)
		}
		if !strings.Contains(err.Error(), "session.max_age") {
			t.Errorf("Session.MaxAge=%v: error should mention session.max_age: %v", d, err)
		}
	}
}

// Zero is rejected rather than defaulted because the two readings are opposite:
// an operator writing 0s most likely means "off", but zero does not disable the
// lockout — it makes it engage without blocking anyone (auth_lockout) or never
// engage at all (auth_fail_window). Defaulting would hand back fifteen minutes
// to someone who asked for none, so the server refuses to start and names the
// switch that does what they meant.
func TestValidate_RejectsZeroLockoutDurations(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*Config)
		wantKey string
	}{
		{"zero lockout", func(c *Config) { c.RateLimit.AuthLockout = 0 }, "rate_limit.auth_lockout"},
		{"zero window", func(c *Config) { c.RateLimit.AuthFailWindow = 0 }, "rate_limit.auth_fail_window"},
		{"negative lockout", func(c *Config) { c.RateLimit.AuthLockout = -1 }, "rate_limit.auth_lockout"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultConfig()
			tc.mutate(c)

			err := c.Validate()
			if err == nil {
				t.Fatalf("%s accepted, want a startup error", tc.wantKey)
			}
			if !strings.Contains(err.Error(), tc.wantKey) {
				t.Errorf("error does not name the field: %v", err)
			}
			// The message must point at the switch that does what the operator meant.
			if !strings.Contains(err.Error(), "auth_fail_max: 0") {
				t.Errorf("error does not name the real off switch: %v", err)
			}
		})
	}
}

// The shipped defaults must pass their own validation.
func TestValidate_DefaultsPass(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("DefaultConfig does not validate: %v", err)
	}
}

// auth_fail_max: 0 is the documented way to disable the lockout, and it is what
// validateRateLimit's own error message recommends. Zeroing the durations
// afterwards is the natural next step, so it must not be a startup failure.
func TestValidate_ZeroDurationsAcceptedWhenLockoutIsDisabled(t *testing.T) {
	c := DefaultConfig()
	c.RateLimit.AuthFailMax = 0
	c.RateLimit.AuthLockout = 0
	c.RateLimit.AuthFailWindow = 0

	if err := c.Validate(); err != nil {
		t.Fatalf("rejected the configuration its own error message recommends: %v", err)
	}
}

// A positive-but-tiny cap is the same fail-open a zero duration is, just
// quieter: the tracker would sit permanently at capacity, evicting on every new
// identity, reported only by a log line.
func TestValidate_RejectsTinyTrackedIdentitiesCap(t *testing.T) {
	c := DefaultConfig()
	c.RateLimit.MaxTrackedIdentities = 100

	err := c.Validate()
	if err == nil {
		t.Fatal("accepted max_tracked_identities: 100")
	}
	if !strings.Contains(err.Error(), "rate_limit.max_tracked_identities") {
		t.Errorf("error does not name the field: %v", err)
	}
}

// Zero means "use the built-in default" and must stay acceptable — the floor
// applies only to a value the operator actually set.
func TestValidate_UnsetTrackedIdentitiesCapAccepted(t *testing.T) {
	c := DefaultConfig()
	c.RateLimit.MaxTrackedIdentities = 0

	if err := c.Validate(); err != nil {
		t.Fatalf("rejected an unset cap: %v", err)
	}
}

// Zero does not disable the throughput limiter, it bricks it: x/time/rate reads
// Limit(0) as "never refill", so a source address spends its burst and is denied
// for the process lifetime, and a zero burst denies from the first request. The
// field was documented "0 = no limit", so an operator could have taken their
// public API down by following the comment.
func TestValidate_RejectsNonPositiveThroughputLimits(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*Config)
		wantKey string
	}{
		{"zero rps", func(c *Config) { c.RateLimit.RequestsPerSecond = 0 }, "rate_limit.requests_per_second"},
		{"negative rps", func(c *Config) { c.RateLimit.RequestsPerSecond = -1 }, "rate_limit.requests_per_second"},
		{"zero burst", func(c *Config) { c.RateLimit.Burst = 0 }, "rate_limit.burst"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultConfig()
			tc.mutate(c)

			err := c.Validate()
			if err == nil {
				t.Fatalf("%s accepted, want a startup error", tc.wantKey)
			}
			if !strings.Contains(err.Error(), tc.wantKey) {
				t.Errorf("error does not name the field: %v", err)
			}
			// It must name the switch that actually turns the limiter off.
			if !strings.Contains(err.Error(), "rate_limit.enabled: false") {
				t.Errorf("error does not name the real off switch: %v", err)
			}
		})
	}
}

// With the limiter off the values are inert, so they must not block startup —
// the same reasoning that skips the lockout durations when auth_fail_max is 0.
func TestValidate_ThroughputLimitsIgnoredWhenDisabled(t *testing.T) {
	c := DefaultConfig()
	c.RateLimit.Enabled = false
	c.RateLimit.RequestsPerSecond = 0
	c.RateLimit.Burst = 0

	if err := c.Validate(); err != nil {
		t.Fatalf("rejected inert values on a disabled limiter: %v", err)
	}
}
