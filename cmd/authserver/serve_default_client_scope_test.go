package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/config"
)

// The warning marks a deprecation, so it has to fire on exactly the
// deployments that will break at v0.3.0: a door open for self-registration,
// and no ceiling to give the clients it creates.
func TestWarnIfNoDefaultClientScope(t *testing.T) {
	tests := []struct {
		name               string
		dcrMode            string
		cimdEnabled        bool
		defaultClientScope string
		wantWarn           bool
	}{
		{"open with no ceiling warns", "open", true, "", true},
		// "" registers nothing: Config.Validate rejects it, and both
		// DCRService.enforceMode and CIMDService.VerifyCIMD fail closed on an
		// unrecognized mode. Warning would point at a door that is shut.
		{"empty mode does not warn", "", true, "", false},
		{"approved_redirects warns", "approved_redirects", false, "", true},
		// CIMD enforces the DCR mode too — VerifyCIMD refuses under admin_only
		// before it fetches — so cimd.enabled alone opens no door. Warning here
		// would tell an operator to set the mode they already have.
		{"admin_only with cimd on does not warn", "admin_only", true, "", false},
		{"admin_only with cimd off does not warn", "admin_only", false, "", false},
		{"ceiling set suppresses the warning", "open", true, "tools/read", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

			cfg := &config.Config{}
			cfg.CIMD.Enabled = tt.cimdEnabled
			cfg.OAuth.DefaultClientScope = tt.defaultClientScope

			// The mode comes from the provider, not the config: it is runtime
			// state that an operator can change through the admin API, and the
			// warning has to see what the server will actually enforce.
			modes := static.NewDCRModeProvider(tt.dcrMode, nil)
			warnIfNoDefaultClientScope(context.Background(), logger, modes, cfg)

			out := buf.String()
			gotWarn := strings.Contains(out, "level=WARN") &&
				strings.Contains(out, "oauth.default_client_scope is empty")
			if gotWarn != tt.wantWarn {
				t.Fatalf("wantWarn=%v, gotWarn=%v\nlog output:\n%s", tt.wantWarn, gotWarn, out)
			}

			if tt.wantWarn {
				// An operator reading one line must learn that this is scheduled,
				// which release changes it, and what to set. Without the version
				// it reads as advice they can defer indefinitely.
				for _, want := range []string{
					"DEPRECATION",
					"v0.3.0",
					"AUTHPLANE_OAUTH_DEFAULT_CLIENT_SCOPE",
				} {
					if !strings.Contains(out, want) {
						t.Errorf("warning is missing %q, which an operator needs to act on it:\n%s",
							want, out)
					}
				}
			}
		})
	}
}

// DefaultConfig() must stay valid: Load() builds on it, so an invalid default
// would stop `authserver serve` with no --config from booting. It ships with
// dcr.mode open and no ceiling, which is exactly the warned combination — the
// warning is the reason that is allowed to be valid.
func TestDefaultConfigWarnsButRemainsValid(t *testing.T) {
	cfg := config.DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultConfig() must remain valid: %v", err)
	}

	var buf bytes.Buffer
	warnIfNoDefaultClientScope(
		context.Background(),
		slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
		static.NewDCRModeProvider(cfg.DCR.Mode, cfg.DCR.ApprovedRedirects),
		cfg)
	if !strings.Contains(buf.String(), "oauth.default_client_scope is empty") {
		t.Errorf("DefaultConfig() ships dcr.mode=%q with no ceiling and must warn:\n%s",
			cfg.DCR.Mode, buf.String())
	}
}
