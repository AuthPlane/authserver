package config

import (
	"strings"
	"testing"
	"time"
)

// The shipped defaults must stay identical to the bounds the audit service
// applies when no provider is wired (services.defaultAuditSinceWindow /
// maxAuditSinceWindow). An operator who sets neither key must see exactly the
// behavior they had before the keys existed, so drift here is a silent
// behavior change for every deployment that never touched the config.
func TestDefaultAuditLookbackMatchesServiceBuiltins(t *testing.T) {
	cfg := DefaultConfig()
	if got, want := cfg.Admin.AuditDefaultLookback, 24*time.Hour; got != want {
		t.Errorf("Admin.AuditDefaultLookback default = %v, want %v", got, want)
	}
	if got, want := cfg.Admin.AuditMaxLookback, 30*24*time.Hour; got != want {
		t.Errorf("Admin.AuditMaxLookback default = %v, want %v", got, want)
	}
}

func TestEnvOverrideAdminAuditLookback(t *testing.T) {
	t.Setenv("AUTHPLANE_ADMIN_AUDIT_DEFAULT_LOOKBACK", "72h")
	t.Setenv("AUTHPLANE_ADMIN_AUDIT_MAX_LOOKBACK", "8760h")
	cfg := DefaultConfig()
	if err := loadFromEnv(cfg); err != nil {
		t.Fatalf("loadFromEnv: %v", err)
	}
	if got, want := cfg.Admin.AuditDefaultLookback, 72*time.Hour; got != want {
		t.Errorf("AuditDefaultLookback after env = %v, want %v", got, want)
	}
	if got, want := cfg.Admin.AuditMaxLookback, 8760*time.Hour; got != want {
		t.Errorf("AuditMaxLookback after env = %v, want %v", got, want)
	}
}

// A unit-less value (the seconds form time.ParseDuration rejects) must be a
// boot failure naming the variable, not a silent revert. An operator widening
// the window for an audit exporter would otherwise be left at 30 days while
// believing the export covers a year.
func TestEnvAdminAuditLookback_UnparseableIsBootError(t *testing.T) {
	for _, name := range []string{
		"AUTHPLANE_ADMIN_AUDIT_DEFAULT_LOOKBACK",
		"AUTHPLANE_ADMIN_AUDIT_MAX_LOOKBACK",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "86400")
			cfg := DefaultConfig()
			err := loadFromEnv(cfg)
			if err == nil {
				t.Fatal("expected a boot error for a unit-less duration, got nil (silent revert)")
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("error should name the offending env var: %v", err)
			}
		})
	}
}

// Zero means "package default" to the provider, not "unbounded", so an explicit
// zero from YAML would silently restore the built-in bound rather than remove
// it. Validate rejects it instead of resolving it invisibly.
func TestValidateRejectsNonPositiveAuditLookback(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(*Config)
		want  string
	}{
		{"zero default", func(c *Config) { c.Admin.AuditDefaultLookback = 0 }, "admin.audit_default_lookback"},
		{"negative default", func(c *Config) { c.Admin.AuditDefaultLookback = -time.Hour }, "admin.audit_default_lookback"},
		{"zero max", func(c *Config) { c.Admin.AuditMaxLookback = 0 }, "admin.audit_max_lookback"},
		{"negative max", func(c *Config) { c.Admin.AuditMaxLookback = -time.Hour }, "admin.audit_max_lookback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAuditConfig()
			tc.apply(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatal("expected a validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should mention %s: %v", tc.want, err)
			}
		})
	}
}

// A default wider than the max is contradictory — the service clamps the
// default down, so the feed would answer an omitted since with a narrower
// window than the operator configured. Reject rather than resolve silently.
func TestValidateRejectsAuditDefaultBeyondMax(t *testing.T) {
	cfg := validAuditConfig()
	cfg.Admin.AuditDefaultLookback = 60 * 24 * time.Hour
	cfg.Admin.AuditMaxLookback = 30 * 24 * time.Hour

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected a validation error for default > max")
	}
	if !strings.Contains(err.Error(), "must not exceed") {
		t.Errorf("error should explain the ordering constraint: %v", err)
	}
}

// A widened window is a legitimate configuration and must validate — this is
// the whole point of the keys existing.
func TestValidateAcceptsWidenedAuditWindow(t *testing.T) {
	cfg := validAuditConfig()
	cfg.Admin.AuditDefaultLookback = 7 * 24 * time.Hour
	cfg.Admin.AuditMaxLookback = 365 * 24 * time.Hour

	if err := cfg.Validate(); err != nil {
		t.Fatalf("a year-long audit window should validate: %v", err)
	}
}

// validAuditConfig returns a config that passes Validate (see
// TestDefaultConfigIsValid), so each test above fails only on the audit bound
// it deliberately breaks.
func validAuditConfig() *Config { return DefaultConfig() }
