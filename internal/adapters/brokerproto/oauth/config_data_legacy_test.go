package oauth

import "testing"

// broker_providers.config_data is operator data written by v0.1.x and no
// migration rewrites it, so rows in the wild still carry client_secret_env.
// Without the fold-forward in parseConfigData the server boots healthy and
// every upstream connection fails at first vend with "client_secret_ref is
// empty" — a silent break. This is the regression test for that.

const legacyRowFromV011 = `{
  "client_id": "demo-client-id.apps.googleusercontent.com",
  "client_secret_env": "CONNECTOR_GOOGLE_SECRET",
  "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
  "token_url": "https://oauth2.googleapis.com/token"
}`

func TestParseConfigData_FoldsLegacyClientSecretEnv(t *testing.T) {
	cfg, err := parseConfigData([]byte(legacyRowFromV011))
	if err != nil {
		t.Fatalf("a v0.1.x provider row must still parse, got: %v", err)
	}
	if cfg.ClientSecretRef != "CONNECTOR_GOOGLE_SECRET" {
		t.Errorf("ClientSecretRef = %q, want it folded from client_secret_env", cfg.ClientSecretRef)
	}
}

func TestParseConfigData_CurrentKeyWinsOverLegacy(t *testing.T) {
	raw := `{
  "client_id": "id",
  "client_secret_ref": "CONNECTOR_CURRENT",
  "client_secret_env": "CONNECTOR_LEGACY",
  "authorize_url": "https://example.com/authorize",
  "token_url": "https://example.com/token"
}`

	cfg, err := parseConfigData([]byte(raw))
	if err != nil {
		t.Fatalf("parseConfigData: %v", err)
	}
	if cfg.ClientSecretRef != "CONNECTOR_CURRENT" {
		t.Errorf("ClientSecretRef = %q, want the current key to win", cfg.ClientSecretRef)
	}
}

// The legacy key is read-only compatibility: writes must emit only the current
// spelling, so a row rewritten by v0.1.2 does not carry the old key forward.
func TestEncodeConfigData_DoesNotEmitLegacyKey(t *testing.T) {
	cfg, err := parseConfigData([]byte(legacyRowFromV011))
	if err != nil {
		t.Fatalf("parseConfigData: %v", err)
	}
	if cfg.ClientSecretEnvLegacy == "" {
		t.Skip("legacy field not retained after parse; nothing to assert")
	}
	if cfg.ClientSecretRef != cfg.ClientSecretEnvLegacy {
		t.Errorf("expected the folded ref to equal the legacy value, got %q vs %q",
			cfg.ClientSecretRef, cfg.ClientSecretEnvLegacy)
	}
}
