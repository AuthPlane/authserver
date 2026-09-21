package config

import "testing"

// oauth.default_client_scope is stamped onto clients verbatim and validated by
// no other layer, so a malformed value fails silently and late: every client
// registered afterwards is refused at /oauth/authorize, while the startup
// warning and the admin notice stay quiet because both only fire when the
// value is empty.
func TestValidateDefaultClientScope(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		status FeatureStatus
	}{
		{"unset is a supported posture", "", FeatureDisabled},
		{"single scope", "tools/read", FeatureEnabled},
		{"space separated", "tools/read tools/write", FeatureEnabled},
		{"extra whitespace is harmless", "  tools/read   tools/write  ", FeatureEnabled},
		// The failure this check exists for: comma is a legal scope character,
		// so only a rule about separators catches it.
		{"comma separated", "tools/read,tools/write", FeatureMisconfigured},
		{"comma inside one token", "tools/read, tools/write", FeatureMisconfigured},
		// A semicolon is legal under the charset and is not a plausible
		// mistyped separator, so refusing it would be this check inventing a
		// rule the spec does not have — and refusing to boot on it would
		// strand a deployment whose scope names legitimately contain one.
		{"semicolon is legal and boots", "tools/read;write", FeatureEnabled},
		{"quote is outside the charset", `tools/"read"`, FeatureMisconfigured},
		{"backslash is outside the charset", `tools\read`, FeatureMisconfigured},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{}
			cfg.OAuth.DefaultClientScope = tt.value
			got := validateDefaultClientScope(cfg)
			if got.Status != tt.status {
				t.Fatalf("status = %v, want %v (value %q, remediation %q)",
					got.Status, tt.status, tt.value, got.Remediation)
			}
			if got.Status == FeatureMisconfigured && got.Remediation == "" {
				t.Error("a misconfiguration must carry remediation text naming the fix")
			}
		})
	}
}

// SelfCheck aborts boot on any FeatureMisconfigured, so the new check has to be
// wired into it — not merely defined.
func TestSelfCheckIncludesDefaultClientScope(t *testing.T) {
	cfg := *DefaultConfig()
	cfg.OAuth.DefaultClientScope = "tools/read,tools/write"
	bad := MisconfiguredChecks(SelfCheck(cfg))
	for _, c := range bad {
		if c.Name == "oauth.default_client_scope" {
			return
		}
	}
	t.Fatalf("a comma-separated default_client_scope must fail SelfCheck; got %+v", bad)
}
