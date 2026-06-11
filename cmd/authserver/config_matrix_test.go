package main

import (
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/config"
)

// config_matrix_test.go is the  Track 6 (Required-config matrix)
// cadence anchor per the operator-test plan. Track 6's
// goal: every combination of optional config either works or
// fails-on-boot with a clear error. Zero silent-disable.
//
// This file lands the minimum the gate requires (≥1 passing test
// covering the pass + fail-on-boot pattern). Full per-feature matrix
// (the eight cases the plan lists — broker_providers without
// data_encryption.driver, token_exchange grant-type mismatches,
// dcr.mode=closed + DCR request, CORS empty + browser-flow enabled,
// etc.) belongs in follow-up PRs.
//
// Each case names the config combination it exercises + the expected
// outcome on Validate(). The "fail-on-boot" cases assert that the
// error string contains an operator-actionable substring — generic
// "invalid config" doesn't help; "data_encryption.driver must be set
// when broker_providers are configured" does.

func TestConfigMatrix(t *testing.T) {
	cases := []struct {
		name string
		// mutate is applied to a fresh DefaultConfig() before
		// validation. nil = pass-through (i.e., baseline default).
		mutate func(*config.Config)
		// wantErr nil = expect Validate() to succeed; non-nil = error
		// must contain this substring.
		wantErrSubstring string
	}{
		{
			name:             "default-config-is-valid",
			mutate:           nil,
			wantErrSubstring: "",
		},
		{
			name: "missing-issuer-fails",
			mutate: func(c *config.Config) {
				c.Server.Issuer = ""
			},
			wantErrSubstring: "server.issuer",
		},
		{
			name: "invalid-storage-driver-fails",
			mutate: func(c *config.Config) {
				c.Storage.Driver = "in-memory" // unsupported value
			},
			wantErrSubstring: "storage.driver",
		},
		{
			name: "postgres-driver-without-dsn-fails",
			mutate: func(c *config.Config) {
				c.Storage.Driver = "postgres"
				c.Storage.Postgres.DSN = ""
			},
			wantErrSubstring: "storage.postgres.dsn",
		},
		{
			name: "postgres-key-store-without-postgres-driver-fails",
			mutate: func(c *config.Config) {
				c.Storage.Driver = "sqlite"
				c.Signing.KeyStore = "postgres_key"
			},
			wantErrSubstring: "postgres_key requires storage.driver=postgres",
		},
		{
			name: "invalid-signing-algorithm-fails",
			mutate: func(c *config.Config) {
				c.Signing.Algorithm = "HS256" // not in the allowed set
			},
			wantErrSubstring: "signing.algorithm",
		},
		{
			name: "dcr-approved-redirects-without-list-fails",
			mutate: func(c *config.Config) {
				c.DCR.Mode = "approved_redirects"
				c.DCR.ApprovedRedirects = nil
			},
			wantErrSubstring: "dcr.approved_redirects",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			if tc.mutate != nil {
				tc.mutate(cfg)
			}
			err := cfg.Validate()
			if tc.wantErrSubstring == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tc.wantErrSubstring)
			}
			if !strings.Contains(err.Error(), tc.wantErrSubstring) {
				t.Errorf("Validate() = %v, want error containing %q", err, tc.wantErrSubstring)
			}
		})
	}
}
