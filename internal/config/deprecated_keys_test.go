package config

import "testing"

// v0.1.x shipped oidc.client_secret_env. v0.1.2 renamed it to
// client_secret_ref; YAML decoding is lenient, so without the normalization in
// normalizeDeprecated the old key is silently dropped and boot then aborts on
// "client_secret or client_secret_ref is required" — taking every federated
// login deployment down on upgrade. These tests pin the shim.

func oidcYAML(t *testing.T, oidcBody string) string {
	t.Helper()
	return writeTempYAML(t, strongConfigPrelude()+oidcBody)
}

func TestLoad_LegacyOIDCClientSecretEnv_StillBoots(t *testing.T) {
	path := oidcYAML(t, `oidc:
  enabled: true
  issuer: "https://accounts.google.com"
  client_id: "test-client-id"
  client_secret_env: "OIDC_CLIENT_SECRET"
  redirect_uri: "https://auth.example.com/oauth/oidc/callback"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("a v0.1.x config with client_secret_env must still load, got: %v", err)
	}
	if cfg.OIDC.ClientSecretRef != "OIDC_CLIENT_SECRET" {
		t.Errorf("ClientSecretRef = %q, want it folded from client_secret_env", cfg.OIDC.ClientSecretRef)
	}
	if got := cfg.LegacyOIDCSecretRef(); got != "OIDC_CLIENT_SECRET" {
		t.Errorf("LegacyOIDCSecretRef() = %q, want the ref marked legacy-sourced", got)
	}
	used := cfg.DeprecatedKeysUsed()
	if len(used) != 1 {
		t.Fatalf("DeprecatedKeysUsed() = %v, want exactly one migration hint", used)
	}
}

// v0.1.x documented client_secret_env as taking precedence over an inline
// client_secret. v0.1.2 made the two mutually exclusive, so a config setting
// both would newly fail to boot unless the old precedence is preserved.
func TestLoad_LegacyOIDCEnv_TakesPrecedenceOverInlineSecret(t *testing.T) {
	path := oidcYAML(t, `oidc:
  enabled: true
  issuer: "https://accounts.google.com"
  client_id: "test-client-id"
  client_secret: "inline-value"
  client_secret_env: "OIDC_CLIENT_SECRET"
  redirect_uri: "https://auth.example.com/oauth/oidc/callback"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("client_secret + client_secret_env must keep v0.1.x precedence, got: %v", err)
	}
	if cfg.OIDC.ClientSecret != "" {
		t.Errorf("ClientSecret = %q, want cleared so the env ref wins as it did in v0.1.x", cfg.OIDC.ClientSecret)
	}
	if cfg.OIDC.ClientSecretRef != "OIDC_CLIENT_SECRET" {
		t.Errorf("ClientSecretRef = %q, want OIDC_CLIENT_SECRET", cfg.OIDC.ClientSecretRef)
	}
}

// The current key must win, and must not be flagged as legacy-sourced (which
// would exempt it from the env-var naming rule).
func TestLoad_CurrentRefWinsAndIsNotLegacy(t *testing.T) {
	path := oidcYAML(t, `oidc:
  enabled: true
  issuer: "https://accounts.google.com"
  client_id: "test-client-id"
  client_secret_ref: "CONNECTOR_OIDC_SECRET"
  redirect_uri: "https://auth.example.com/oauth/oidc/callback"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.OIDC.ClientSecretRef != "CONNECTOR_OIDC_SECRET" {
		t.Errorf("ClientSecretRef = %q", cfg.OIDC.ClientSecretRef)
	}
	if got := cfg.LegacyOIDCSecretRef(); got != "" {
		t.Errorf("LegacyOIDCSecretRef() = %q, want empty for a current-key config", got)
	}
	if used := cfg.DeprecatedKeysUsed(); len(used) != 0 {
		t.Errorf("DeprecatedKeysUsed() = %v, want none", used)
	}
}

func TestLoadBrokerProviderFromEnv_LegacyClientSecretEnvVar(t *testing.T) {
	t.Setenv("AUTHPLANE_BROKER_PROVIDER_SLUG", "github")
	t.Setenv("AUTHPLANE_BROKER_PROVIDER_CLIENT_ID", "Iv1.test")
	t.Setenv("AUTHPLANE_BROKER_PROVIDER_CLIENT_SECRET_ENV", "CONNECTOR_GITHUB_SECRET")
	t.Setenv("AUTHPLANE_BROKER_PROVIDER_AUTHORIZE_URL", "https://github.com/login/oauth/authorize")
	t.Setenv("AUTHPLANE_BROKER_PROVIDER_TOKEN_URL", "https://github.com/login/oauth/access_token")

	cfg := DefaultConfig()
	if err := loadFromEnv(cfg); err != nil {
		t.Fatalf("loadFromEnv: %v", err)
	}
	if len(cfg.BrokerProviders) != 1 {
		t.Fatalf("BrokerProviders = %d, want 1 seeded from the deprecated env var", len(cfg.BrokerProviders))
	}
	got := cfg.BrokerProviders[0].ConfigData["client_secret_ref"]
	if got != "CONNECTOR_GITHUB_SECRET" {
		t.Errorf("client_secret_ref = %v, want the deprecated _ENV var folded forward", got)
	}
}
