package config

import (
	"strings"
	"testing"
	"time"
)

// findCheck returns the FeatureCheck with the given name or fails the test.
func findCheck(t *testing.T, checks []FeatureCheck, name string) FeatureCheck {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no FeatureCheck named %q in %+v", name, checks)
	return FeatureCheck{}
}

// TestSelfCheck_DefaultConfig — a fresh DefaultConfig with no broker
// resources should boot cleanly: every feature is either Enabled (the few
// that are unconditional) or Disabled (the ones flag-driven off).
func TestSelfCheck_DefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	checks := SelfCheck(*cfg)
	if bad := MisconfiguredChecks(checks); len(bad) > 0 {
		t.Fatalf("default config should be valid, got misconfigured: %+v", bad)
	}
}

// TestSelfCheck_DataEncryption_RequiredForBrokerResources — the canonical
// repro: empty data_encryption.driver + a Broker resource ⇒ boot
// must fail with a misconfigured check naming the driver key.
func TestSelfCheck_DataEncryption_RequiredForBrokerResources(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Resources = []ResourceConfigUnified{{
		Slug:        "google-calendar",
		BackendKind: "broker",
		Policy: PolicyConfig{
			Connect: ConnectPolicyConfig{
				AllowedReturnURLs: []string{"http://localhost:8084/connected"},
			},
		},
	}}
	cfg.Connect = ConnectConfig{
		StateSecret:     strings.Repeat("a", 32),
		RedirectBaseURL: "http://localhost:9000",
	}

	checks := SelfCheck(*cfg)
	got := findCheck(t, checks, "data_encryption")
	if got.Status != FeatureMisconfigured {
		t.Fatalf("data_encryption: want Misconfigured, got %s (%+v)", got.Status, got)
	}
	if got.MissingKey != "data_encryption.driver" {
		t.Errorf("MissingKey: want data_encryption.driver, got %q", got.MissingKey)
	}
	if got.Remediation == "" {
		t.Error("Remediation should be populated")
	}
}

// TestSelfCheck_DataEncryption_AllowedDisabledWithoutBrokers — without any
// Broker resource and with no connect.* keys set, an empty driver is just
// "disabled" (operator opted out of at-rest encryption); boot proceeds.
func TestSelfCheck_DataEncryption_AllowedDisabledWithoutBrokers(t *testing.T) {
	cfg := DefaultConfig()
	checks := SelfCheck(*cfg)
	got := findCheck(t, checks, "data_encryption")
	if got.Status != FeatureDisabled {
		t.Fatalf("data_encryption: want Disabled, got %s (%+v)", got.Status, got)
	}
}

// TestSelfCheck_DataEncryption_AESMasterRequiresKeyEnv — driver=aes_master
// without key_env is misconfigured.
func TestSelfCheck_DataEncryption_AESMasterRequiresKeyEnv(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DataEncryption = DataEncryptionConfig{Driver: "aes_master"}
	checks := SelfCheck(*cfg)
	got := findCheck(t, checks, "data_encryption")
	if got.Status != FeatureMisconfigured {
		t.Fatalf("want Misconfigured, got %s", got.Status)
	}
	if got.MissingKey != "data_encryption.aes_master.key_env" {
		t.Errorf("MissingKey: got %q", got.MissingKey)
	}
}

// TestSelfCheck_DataEncryption_UnknownDriver — unrecognized driver name.
func TestSelfCheck_DataEncryption_UnknownDriver(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DataEncryption = DataEncryptionConfig{Driver: "nonsense"}
	checks := SelfCheck(*cfg)
	got := findCheck(t, checks, "data_encryption")
	if got.Status != FeatureMisconfigured {
		t.Fatalf("want Misconfigured, got %s", got.Status)
	}
	if !strings.Contains(got.Remediation, "nonsense") {
		t.Errorf("Remediation should mention bad value: %q", got.Remediation)
	}
}

// TestSelfCheck_Connect_RequiresStateSecret — Broker resource configured
// without connect.state_secret fails boot.
func TestSelfCheck_Connect_RequiresStateSecret(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DataEncryption = DataEncryptionConfig{
		Driver:    "aes_master",
		AESMaster: AESMasterConfig{KeyEnv: "AUTHPLANE_DATA_ENCRYPTION_KEY"},
	}
	cfg.Resources = []ResourceConfigUnified{{
		Slug:        "google-calendar",
		BackendKind: "broker",
		Policy: PolicyConfig{
			Connect: ConnectPolicyConfig{
				AllowedReturnURLs: []string{"http://localhost:8084/connected"},
			},
		},
	}}

	checks := SelfCheck(*cfg)
	got := findCheck(t, checks, "connect")
	if got.Status != FeatureMisconfigured {
		t.Fatalf("connect: want Misconfigured, got %s (%+v)", got.Status, got)
	}
	if got.MissingKey != "connect.state_secret" {
		t.Errorf("MissingKey: got %q", got.MissingKey)
	}
}

// TestSelfCheck_Connect_RequiresStateSecretMinLen — short secret rejected.
func TestSelfCheck_Connect_RequiresStateSecretMinLen(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DataEncryption = DataEncryptionConfig{
		Driver:    "aes_master",
		AESMaster: AESMasterConfig{KeyEnv: "AUTHPLANE_DATA_ENCRYPTION_KEY"},
	}
	cfg.Connect = ConnectConfig{
		StateSecret:     "short",
		RedirectBaseURL: "http://localhost:9000",
	}
	cfg.Resources = []ResourceConfigUnified{{
		Slug:        "google-calendar",
		BackendKind: "broker",
		Policy: PolicyConfig{
			Connect: ConnectPolicyConfig{AllowedReturnURLs: []string{"http://localhost:8084/connected"}},
		},
	}}

	checks := SelfCheck(*cfg)
	got := findCheck(t, checks, "connect")
	if got.Status != FeatureMisconfigured {
		t.Fatalf("connect: want Misconfigured, got %s", got.Status)
	}
	if !strings.Contains(got.Remediation, "32") {
		t.Errorf("Remediation should mention min length: %q", got.Remediation)
	}
}

// TestSelfCheck_Connect_DisabledWithoutBrokers — no Broker resources and
// no connect config means "operator did not request Connect"; the feature
// is Disabled (not Misconfigured) and boot proceeds.
func TestSelfCheck_Connect_DisabledWithoutBrokers(t *testing.T) {
	cfg := DefaultConfig()
	checks := SelfCheck(*cfg)
	got := findCheck(t, checks, "connect")
	if got.Status != FeatureDisabled {
		t.Fatalf("connect: want Disabled, got %s", got.Status)
	}
}

// TestSelfCheck_TokenExchange_DisabledFlag — Enabled=false is a legitimate
// operator choice; boot proceeds with the feature off.
func TestSelfCheck_TokenExchange_DisabledFlag(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TokenExchange.Enabled = false
	checks := SelfCheck(*cfg)
	got := findCheck(t, checks, "token_exchange")
	if got.Status != FeatureDisabled {
		t.Fatalf("token_exchange: want Disabled, got %s", got.Status)
	}
}

// TestSelfCheck_TokenExchange_EnabledRequiresChainDepth — enabled with
// max_chain_depth=0 (or out of range) is misconfigured.
func TestSelfCheck_TokenExchange_EnabledRequiresChainDepth(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TokenExchange = TokenExchangeConfig{
		Enabled:       true,
		MaxChainDepth: 0,
		TokenExpiry:   time.Hour,
	}
	checks := SelfCheck(*cfg)
	got := findCheck(t, checks, "token_exchange")
	if got.Status != FeatureMisconfigured {
		t.Fatalf("want Misconfigured, got %s", got.Status)
	}
	if got.MissingKey != "token_exchange.max_chain_depth" {
		t.Errorf("MissingKey: got %q", got.MissingKey)
	}
}

// TestSelfCheck_DPoP_EnabledRequiresLifetimes — DPoP on with 0 durations
// would silently accept any-age proofs; treat as misconfigured.
func TestSelfCheck_DPoP_EnabledRequiresLifetimes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DPoP = DPoPConfig{Enabled: true} // both durations zero
	checks := SelfCheck(*cfg)
	got := findCheck(t, checks, "dpop")
	if got.Status != FeatureMisconfigured {
		t.Fatalf("want Misconfigured, got %s", got.Status)
	}
}

// TestSelfCheck_DCR_UnknownMode — an unrecognized DCR mode is a typo
// that would otherwise produce a default-deny at runtime.
func TestSelfCheck_DCR_UnknownMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DCR.Mode = "bogus"
	checks := SelfCheck(*cfg)
	got := findCheck(t, checks, "dcr")
	if got.Status != FeatureMisconfigured {
		t.Fatalf("want Misconfigured, got %s", got.Status)
	}
}

// TestSelfCheck_DCR_ApprovedRedirectsRequiresList — mode=approved_redirects
// without entries denies all DCR registration silently.
func TestSelfCheck_DCR_ApprovedRedirectsRequiresList(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DCR.Mode = "approved_redirects"
	cfg.DCR.ApprovedRedirects = nil
	checks := SelfCheck(*cfg)
	got := findCheck(t, checks, "dcr")
	if got.Status != FeatureMisconfigured {
		t.Fatalf("want Misconfigured, got %s", got.Status)
	}
	if got.MissingKey != "dcr.approved_redirects" {
		t.Errorf("MissingKey: got %q", got.MissingKey)
	}
}

// TestSelfCheck_Resources_BrokerRequiresAllowedReturnURLs — folds
// into the boot self-check: a Broker resource with empty
// policy.connect.allowed_return_urls fails boot, so the demo's first-run
// failure surfaces at startup instead of at first /connect call.
func TestSelfCheck_Resources_BrokerRequiresAllowedReturnURLs(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DataEncryption = DataEncryptionConfig{
		Driver:    "aes_master",
		AESMaster: AESMasterConfig{KeyEnv: "AUTHPLANE_DATA_ENCRYPTION_KEY"},
	}
	cfg.Connect = ConnectConfig{
		StateSecret:     strings.Repeat("a", 32),
		RedirectBaseURL: "http://localhost:9000",
	}
	cfg.Resources = []ResourceConfigUnified{{
		Slug:        "google-calendar",
		BackendKind: "broker",
		// Note: no Policy.Connect.AllowedReturnURLs — the case.
	}}

	checks := SelfCheck(*cfg)
	got := findCheck(t, checks, "resources(seeded)")
	if got.Status != FeatureMisconfigured {
		t.Fatalf("resources: want Misconfigured, got %s (%+v)", got.Status, got)
	}
	if got.MissingKey != "resources[].policy.connect.allowed_return_urls" {
		t.Errorf("MissingKey: got %q", got.MissingKey)
	}
	if !strings.Contains(got.Remediation, "google-calendar") {
		t.Errorf("Remediation should name the offending slug: %q", got.Remediation)
	}
}

// TestSelfCheck_Resources_MintWithoutAllowedReturnURLsIsFine — Mint
// resources don't need allowed_return_urls; only Broker resources do.
func TestSelfCheck_Resources_MintWithoutAllowedReturnURLsIsFine(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Resources = []ResourceConfigUnified{{
		Slug:        "my-mcp",
		BackendKind: "mint",
	}}
	checks := SelfCheck(*cfg)
	got := findCheck(t, checks, "resources(seeded)")
	if got.Status != FeatureEnabled {
		t.Fatalf("mint resources should pass: got %s (%+v)", got.Status, got)
	}
}

// TestFormatReport_Stable — the rendered block lists every feature with
// aligned columns and stable status text. Pinning helps the boot integration
// test assert structure without coupling to exact bytes.
func TestFormatReport_Stable(t *testing.T) {
	checks := []FeatureCheck{
		{Name: "data_encryption", Status: FeatureEnabled, Detail: "driver=aes_master"},
		{Name: "connect", Status: FeatureDisabled, Detail: "no broker resources"},
	}
	report := FormatReport(checks)
	if !strings.Contains(report, "=== authserver feature self-check ===") {
		t.Error("report missing header")
	}
	if !strings.Contains(report, "data_encryption") || !strings.Contains(report, "enabled") {
		t.Error("report missing feature/status")
	}
	if !strings.Contains(report, "connect") || !strings.Contains(report, "disabled") {
		t.Error("report missing connect/disabled")
	}
}

// TestFormatMisconfiguredReport_NamesEveryKey — the fatal-log block lists
// every missing key + remediation so the operator can fix all problems in
// a single restart.
func TestFormatMisconfiguredReport_NamesEveryKey(t *testing.T) {
	bad := []FeatureCheck{
		{
			Name:        "data_encryption",
			Status:      FeatureMisconfigured,
			MissingKey:  "data_encryption.driver",
			Remediation: "set data_encryption.driver=aes_master",
		},
		{
			Name:        "connect",
			Status:      FeatureMisconfigured,
			MissingKey:  "connect.state_secret",
			Remediation: "set a 32+ char HMAC key",
		},
	}
	report := FormatMisconfiguredReport(bad)
	for _, want := range []string{
		"data_encryption.driver",
		"connect.state_secret",
		"set data_encryption.driver=aes_master",
		"set a 32+ char HMAC key",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %q\n%s", want, report)
		}
	}
}
