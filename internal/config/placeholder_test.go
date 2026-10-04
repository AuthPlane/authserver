package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The loader never substitutes ${VAR} into the file. A value left in that
// shape, with nothing in the environment replacing it, must stop the boot,
// not become the literal secret.
func TestLoad_RejectsUnexpandedPlaceholder(t *testing.T) {
	unsetEnv(t, "AUTHPLANE_ADMIN_API_KEY", "AUTHPLANE_STORAGE_POSTGRES_DSN", "AUTHPLANE_SESSION_SECRET", "AUTHPLANE_SERVER_ALLOWED_ORIGINS")
	cases := []struct {
		name, yaml, wantPath, wantVal string
	}{
		{"admin api key", "admin:\n  api_key: \"${AUTHPLANE_ADMIN_API_KEY}\"\n", "admin.api_key", "${AUTHPLANE_ADMIN_API_KEY}"},
		{"session secret", "session:\n  secret: \"${SESSION_SECRET}\"\n", "session.secret", "${SESSION_SECRET}"},
		{"embedded in a DSN", "storage:\n  postgres:\n    dsn: \"postgres://u:${POSTGRES_PASSWORD}@db/authserver\"\n", "storage.postgres.dsn", "${POSTGRES_PASSWORD}"},
		{"with default syntax", "admin:\n  api_key: \"${KEY:-fallback}\"\n", "admin.api_key", "${KEY:-fallback}"},
		{"inside a list", "server:\n  allowed_origins:\n    - \"https://ok.example\"\n    - \"${ORIGIN}\"\n", "server.allowed_origins[1]", "${ORIGIN}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "c.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatalf("Load accepted a config with an unexpanded placeholder")
			}
			if !strings.Contains(err.Error(), tc.wantPath) || !strings.Contains(err.Error(), tc.wantVal) {
				t.Fatalf("error should name %s and %q, got: %v", tc.wantPath, tc.wantVal, err)
			}
		})
	}
}

// A dollar sign that is not a placeholder is still a legal value.
func TestLoad_AllowsDollarSignsThatAreNotPlaceholders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	yaml := "admin:\n  enabled: true\n  api_key: \"pa$$word-with-{braces}-and-$dollar\"\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Admin.APIKey != "pa$$word-with-{braces}-and-$dollar" {
		t.Fatalf("value altered: %q", cfg.Admin.APIKey)
	}
}

// A placeholder the matching AUTHPLANE_* variable replaces is never used, so
// it is not an error: the example configs and any compose file that passes
// the variable keep working. The resolved value is the environment's.
func TestLoad_AcceptsPlaceholderOverriddenByEnv(t *testing.T) {
	t.Setenv("AUTHPLANE_ADMIN_API_KEY", "from-the-environment-0123456789")
	path := filepath.Join(t.TempDir(), "c.yaml")
	yaml := "admin:\n  enabled: true\n  api_key: \"${AUTHPLANE_ADMIN_API_KEY}\"\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Admin.APIKey != "from-the-environment-0123456789" {
		t.Fatalf("api key = %q, want the environment value", cfg.Admin.APIKey)
	}
}

// A variable set to the empty string is an override too; the placeholder is
// gone and the boot proceeds to ordinary validation.
func TestLoad_PlaceholderOverriddenByEmptyEnvIsNotLiteral(t *testing.T) {
	t.Setenv("AUTHPLANE_ADMIN_API_KEY", "")
	path := filepath.Join(t.TempDir(), "c.yaml")
	yaml := "admin:\n  api_key: \"${AUTHPLANE_ADMIN_API_KEY}\"\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Admin.APIKey != "" {
		t.Fatalf("api key = %q, want empty", cfg.Admin.APIKey)
	}
}

func unsetEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, k := range keys {
		t.Setenv(k, "") // registers restoration of the original value
		if err := os.Unsetenv(k); err != nil {
			t.Fatal(err)
		}
	}
}
