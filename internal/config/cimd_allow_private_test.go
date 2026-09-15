package config

import (
	"strings"
	"testing"
)

// allow_private_addresses turns off SSRF address filtering for CIMD, so its
// default is part of the security posture: a config that does not mention it
// must come back false.
//
// The issuer is localhost because require_https: false is only legal there —
// which is the point being made from the other side: relaxing the scheme
// control, in the one place that is allowed to, still leaves the address
// control at its default.
func TestCIMDAllowPrivateAddresses_DefaultsFalse(t *testing.T) {
	path := writeTempYAML(t, `server:
  issuer: "http://localhost:9000"
admin:
  api_key: "a-very-strong-admin-key-for-tests"
cimd:
  enabled: true
  require_https: false
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.CIMD.AllowPrivateAddresses {
		t.Error("cimd.allow_private_addresses must default to false — it disables SSRF address filtering")
	}
	// The point of the whole change: the two knobs are independent, so setting
	// require_https must leave the address control at its default.
	if cfg.CIMD.RequireHTTPS {
		t.Error("require_https: false was not honored — test fixture is wrong")
	}
}

// The issuer is localhost because allow_private_addresses: true is only legal
// there — see TestValidate_CIMDAllowPrivateAddresses for that rule.
func TestCIMDAllowPrivateAddresses_YAML(t *testing.T) {
	path := writeTempYAML(t, `server:
  issuer: "http://localhost:9000"
admin:
  api_key: "a-very-strong-admin-key-for-tests"
cimd:
  enabled: true
  allow_private_addresses: true
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.CIMD.AllowPrivateAddresses {
		t.Error("cimd.allow_private_addresses: true was not decoded")
	}
	// Orthogonality, from the other side: opting into private addresses must
	// not weaken the scheme check.
	if !cfg.CIMD.RequireHTTPS {
		t.Error("allow_private_addresses must not change require_https from its default")
	}
}

func TestCIMDAllowPrivateAddresses_EnvOverride(t *testing.T) {
	t.Setenv("AUTHPLANE_CIMD_ALLOW_PRIVATE_ADDRESSES", "true")
	cfg := CIMDConfig{}
	loadCIMDFromEnv(&cfg)
	if !cfg.AllowPrivateAddresses {
		t.Error("AUTHPLANE_CIMD_ALLOW_PRIVATE_ADDRESSES=true did not set AllowPrivateAddresses")
	}
}

// The flag disables SSRF address filtering on a fetch an unauthenticated caller
// drives: /oauth/authorize resolves the client, and so the document, before it
// decides whether a login is required. So it carries the same boot-time rule as
// require_https — permitted on localhost, refused anywhere else.
func TestValidate_CIMDAllowPrivateAddresses(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		issuer       string
		enabled      bool
		allowPrivate bool
		wantErr      bool
	}{
		{"production issuer with private addresses allowed", "https://auth.example.com", true, true, true},
		{"production issuer on the default", "https://auth.example.com", true, false, false},
		{"localhost issuer with private addresses allowed", "http://localhost:9000", true, true, false},
		{"localhost issuer on the default", "http://localhost:9000", true, false, false},
		// CIMD off makes the flag inert: no fetch happens, so there is nothing
		// to refuse to boot over.
		{"cimd disabled with private addresses allowed", "https://auth.example.com", false, true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := DefaultConfig()
			cfg.Server.Issuer = tc.issuer
			cfg.CIMD.Enabled = tc.enabled
			cfg.CIMD.AllowPrivateAddresses = tc.allowPrivate
			cfg.Session.Secret = "a-sufficiently-long-session-secret"
			cfg.Session.Secure = !isLocalhostIssuer(tc.issuer)

			err := cfg.Validate()
			mentions := err != nil && strings.Contains(err.Error(), "cimd.allow_private_addresses")

			if tc.wantErr && !mentions {
				t.Errorf("expected a cimd.allow_private_addresses validation error, got: %v", err)
			}
			if !tc.wantErr && mentions {
				t.Errorf("unexpected cimd.allow_private_addresses validation error: %v", err)
			}
		})
	}
}
