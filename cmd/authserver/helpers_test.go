package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/authplane/authserver/internal/config"
)

// TestLoadConfig_EnforcesAdminAPIKeyPolicy guards the sole OSS enforcement seam:
// loadConfig must run ValidateAdminAPIKey after config.Load. A localhost issuer
// keeps Validate() happy, while a known-weak admin key trips the admin-key
// policy (whose weak-secret check is issuer-independent) — so a green result
// proves loadConfig wired the policy call.
func TestLoadConfig_EnforcesAdminAPIKeyPolicy(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Admin.Enabled = true
	cfg.Admin.APIKey = "changeme" // known weak/default → rejected by ValidateAdminAPIKey

	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	old := cfgFile
	cfgFile = path
	t.Cleanup(func() { cfgFile = old })

	if _, err := loadConfig(); err == nil {
		t.Fatal("loadConfig must reject a weak admin api_key")
	} else if !strings.Contains(err.Error(), "weak/default") {
		t.Errorf("expected admin api_key policy error from loadConfig, got: %v", err)
	}
}
