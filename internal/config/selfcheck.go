package config

import (
	"fmt"
	"strings"
)

// FeatureStatus is the boot-time disposition of a single subsystem.
type FeatureStatus int

const (
	// FeatureEnabled — required config is present and the feature will
	// initialize.
	FeatureEnabled FeatureStatus = iota
	// FeatureDisabled — operator opted out (e.g. token_exchange.enabled=false).
	// The feature is intentionally off; runtime endpoints return a typed
	// feature_disabled error pointing at the config key that would re-enable
	// it. Boot proceeds.
	FeatureDisabled
	// FeatureMisconfigured — required config is partially present (or holds
	// an unrecognized value). Boot fails so the operator sees the problem
	// instead of a half-working AS that 200s with empty payloads or 5xxs
	// downstream.
	FeatureMisconfigured
)

func (s FeatureStatus) String() string {
	switch s {
	case FeatureEnabled:
		return "enabled"
	case FeatureDisabled:
		return "disabled"
	case FeatureMisconfigured:
		return "misconfigured"
	default:
		return "unknown"
	}
}

// FeatureCheck is the result of validating one subsystem at boot.
//
// Detail is a short human-readable note shown alongside Status in the
// startup self-check report (e.g. "driver=aes_master" or
// "token_exchange.enabled=false"). MissingKey + Remediation are populated
// only when Status == FeatureMisconfigured and drive the fatal-log block.
type FeatureCheck struct {
	Name        string
	Status      FeatureStatus
	Detail      string
	MissingKey  string
	Remediation string
}

// SelfCheck runs the boot-time validation pass over cfg and returns one
// FeatureCheck per subsystem in stable display order. The caller decides
// whether to fail boot (any FeatureMisconfigured) or proceed.
//
// The set of subsystems is intentionally bounded to those named by
// plus the resource-policy gap from. Additional subsystems
// (OIDC, …) can be added later — every new entry tightens the
// "no silent degradation" contract.
func SelfCheck(cfg Config) []FeatureCheck {
	return []FeatureCheck{
		validateDataEncryption(cfg),
		validateConnect(cfg),
		validateTokenExchange(cfg),
		validateClientCredentials(cfg),
		validateDPoP(cfg),
		validateDCR(cfg),
		validateDefaultClientScope(cfg),
		validateResources(cfg),
		validateXAA(cfg),
	}
}

// brokerResourceConfigured reports whether any seeded Resource is a Broker
// (i.e. needs the Connect feature + at-rest encryption to vend tokens).
func brokerResourceConfigured(cfg Config) bool {
	for _, r := range cfg.Resources {
		if strings.EqualFold(r.BackendKind, "broker") {
			return true
		}
	}
	return false
}

// connectFeatureRequested reports whether the operator has expressed any
// intent to use the upstream-Connect feature. Either a seeded Broker
// resource OR any non-empty connect.* config counts.
func connectFeatureRequested(cfg Config) bool {
	if cfg.Connect.StateSecret != "" || cfg.Connect.RedirectBaseURL != "" || len(cfg.Connect.AllowedReturnURLs) > 0 {
		return true
	}
	return brokerResourceConfigured(cfg)
}

// validateDataEncryption checks the data_encryption block. Empty driver is
// only allowed when nothing in the configuration depends on at-rest
// encryption (no Broker resources, no Connect config). Once the operator
// signals they want Connect, the driver becomes required.
func validateDataEncryption(cfg Config) FeatureCheck {
	const name = "data_encryption"
	needs := connectFeatureRequested(cfg)

	if cfg.DataEncryption.Driver == "" {
		if needs {
			return FeatureCheck{
				Name:        name,
				Status:      FeatureMisconfigured,
				MissingKey:  "data_encryption.driver",
				Remediation: "set data_encryption.driver=aes_master (and data_encryption.aes_master.key_env) — required because Broker resources / connect config are present",
			}
		}
		return FeatureCheck{
			Name:   name,
			Status: FeatureDisabled,
			Detail: "no driver configured",
		}
	}

	switch cfg.DataEncryption.Driver {
	case "aes_master":
		if cfg.DataEncryption.AESMaster.KeyEnv == "" {
			return FeatureCheck{
				Name:        name,
				Status:      FeatureMisconfigured,
				MissingKey:  "data_encryption.aes_master.key_env",
				Remediation: "set data_encryption.aes_master.key_env to the env var holding the 64-hex-char master key",
			}
		}
		return FeatureCheck{
			Name:   name,
			Status: FeatureEnabled,
			Detail: "driver=aes_master",
		}
	case "vault_transit_encrypt":
		if cfg.DataEncryption.VaultTransitEncrypt.Address == "" {
			return FeatureCheck{
				Name:        name,
				Status:      FeatureMisconfigured,
				MissingKey:  "data_encryption.vault_transit_encrypt.address",
				Remediation: "set data_encryption.vault_transit_encrypt.address to the Vault server URL",
			}
		}
		if cfg.DataEncryption.VaultTransitEncrypt.KeyName == "" {
			return FeatureCheck{
				Name:        name,
				Status:      FeatureMisconfigured,
				MissingKey:  "data_encryption.vault_transit_encrypt.key_name",
				Remediation: "set data_encryption.vault_transit_encrypt.key_name to the Transit key name",
			}
		}
		return FeatureCheck{
			Name:   name,
			Status: FeatureEnabled,
			Detail: "driver=vault_transit_encrypt",
		}
	default:
		return FeatureCheck{
			Name:        name,
			Status:      FeatureMisconfigured,
			MissingKey:  "data_encryption.driver",
			Remediation: fmt.Sprintf("unknown driver %q — supported: aes_master, vault_transit_encrypt", cfg.DataEncryption.Driver),
		}
	}
}

// validateConnect checks the connect block. The feature is treated as
// requested whenever any Broker resource is seeded or any connect.* key
// is set. Once requested, state_secret + redirect_base_url are required.
func validateConnect(cfg Config) FeatureCheck {
	const name = "connect"
	if !connectFeatureRequested(cfg) {
		return FeatureCheck{
			Name:   name,
			Status: FeatureDisabled,
			Detail: "no broker resources or connect config",
		}
	}
	if cfg.Connect.StateSecret == "" {
		return FeatureCheck{
			Name:        name,
			Status:      FeatureMisconfigured,
			MissingKey:  "connect.state_secret",
			Remediation: "set connect.state_secret to a 32+ char HMAC key",
		}
	}
	if len(cfg.Connect.StateSecret) < 32 {
		return FeatureCheck{
			Name:        name,
			Status:      FeatureMisconfigured,
			MissingKey:  "connect.state_secret",
			Remediation: "connect.state_secret must be at least 32 characters",
		}
	}
	if cfg.Connect.RedirectBaseURL == "" {
		return FeatureCheck{
			Name:        name,
			Status:      FeatureMisconfigured,
			MissingKey:  "connect.redirect_base_url",
			Remediation: "set connect.redirect_base_url to the AS public base URL (e.g. https://authplane.example.com)",
		}
	}
	return FeatureCheck{
		Name:   name,
		Status: FeatureEnabled,
		Detail: "redirect_base_url=" + cfg.Connect.RedirectBaseURL,
	}
}

// validateTokenExchange checks the token_exchange block. Flag-driven: when
// disabled, that's a legitimate operator choice and we just record it.
// When enabled, max_chain_depth and token_expiry must be sane.
func validateTokenExchange(cfg Config) FeatureCheck {
	const name = "token_exchange"
	if !cfg.TokenExchange.Enabled {
		return FeatureCheck{
			Name:   name,
			Status: FeatureDisabled,
			Detail: "token_exchange.enabled=false",
		}
	}
	if cfg.TokenExchange.MaxChainDepth <= 0 || cfg.TokenExchange.MaxChainDepth > 10 {
		return FeatureCheck{
			Name:        name,
			Status:      FeatureMisconfigured,
			MissingKey:  "token_exchange.max_chain_depth",
			Remediation: "set token_exchange.max_chain_depth to an integer in [1,10]",
		}
	}
	if cfg.TokenExchange.TokenExpiry <= 0 {
		return FeatureCheck{
			Name:        name,
			Status:      FeatureMisconfigured,
			MissingKey:  "token_exchange.token_expiry",
			Remediation: "set token_exchange.token_expiry to a positive duration (e.g. 1h)",
		}
	}
	return FeatureCheck{
		Name:   name,
		Status: FeatureEnabled,
		Detail: fmt.Sprintf("max_chain_depth=%d token_expiry=%s", cfg.TokenExchange.MaxChainDepth, cfg.TokenExchange.TokenExpiry),
	}
}

// validateClientCredentials checks the client_credentials block.
func validateClientCredentials(cfg Config) FeatureCheck {
	const name = "client_credentials"
	if !cfg.ClientCredentials.Enabled {
		return FeatureCheck{
			Name:   name,
			Status: FeatureDisabled,
			Detail: "client_credentials.enabled=false",
		}
	}
	if cfg.ClientCredentials.TokenExpiry <= 0 {
		return FeatureCheck{
			Name:        name,
			Status:      FeatureMisconfigured,
			MissingKey:  "client_credentials.token_expiry",
			Remediation: "set client_credentials.token_expiry to a positive duration (e.g. 1h)",
		}
	}
	return FeatureCheck{
		Name:   name,
		Status: FeatureEnabled,
		Detail: "token_expiry=" + cfg.ClientCredentials.TokenExpiry.String(),
	}
}

// validateDPoP checks the dpop block. When enabled, both nonce_ttl and
// proof_lifetime must be positive — otherwise the runtime accepts proofs
// outside any meaningful freshness window.
func validateDPoP(cfg Config) FeatureCheck {
	const name = "dpop"
	if !cfg.DPoP.Enabled {
		return FeatureCheck{
			Name:   name,
			Status: FeatureDisabled,
			Detail: "dpop.enabled=false",
		}
	}
	if cfg.DPoP.ProofLifetime <= 0 {
		return FeatureCheck{
			Name:        name,
			Status:      FeatureMisconfigured,
			MissingKey:  "dpop.proof_lifetime",
			Remediation: "set dpop.proof_lifetime to a positive duration (e.g. 60s)",
		}
	}
	if cfg.DPoP.NonceTTL <= 0 {
		return FeatureCheck{
			Name:        name,
			Status:      FeatureMisconfigured,
			MissingKey:  "dpop.nonce_ttl",
			Remediation: "set dpop.nonce_ttl to a positive duration (e.g. 60s)",
		}
	}
	return FeatureCheck{
		Name:   name,
		Status: FeatureEnabled,
		Detail: fmt.Sprintf("proof_lifetime=%s require_nonce=%t", cfg.DPoP.ProofLifetime, cfg.DPoP.RequireNonce),
	}
}

// dcrValidModes is the closed set accepted by the DCR service.
var dcrValidModes = map[string]struct{}{
	"":                   {}, // legacy: empty string defaults to "open"
	"open":               {},
	"approved_redirects": {},
	"admin_only":         {},
	"disabled":           {},
}

// validateDCR checks the dcr block. The mode is a closed enum; an
// unrecognized value would otherwise produce a default-deny at runtime
// with no log line.
func validateDCR(cfg Config) FeatureCheck {
	const name = "dcr"
	if _, ok := dcrValidModes[cfg.DCR.Mode]; !ok {
		return FeatureCheck{
			Name:        name,
			Status:      FeatureMisconfigured,
			MissingKey:  "dcr.mode",
			Remediation: fmt.Sprintf("unknown mode %q — supported: open, approved_redirects, admin_only, disabled", cfg.DCR.Mode),
		}
	}
	if cfg.DCR.Mode == "approved_redirects" && len(cfg.DCR.ApprovedRedirects) == 0 {
		return FeatureCheck{
			Name:        name,
			Status:      FeatureMisconfigured,
			MissingKey:  "dcr.approved_redirects",
			Remediation: "approved_redirects mode requires at least one entry in dcr.approved_redirects",
		}
	}
	if cfg.DCR.Mode == "disabled" {
		return FeatureCheck{
			Name:   name,
			Status: FeatureDisabled,
			Detail: "mode=disabled",
		}
	}
	mode := cfg.DCR.Mode
	if mode == "" {
		mode = "open"
	}
	return FeatureCheck{
		Name:   name,
		Status: FeatureEnabled,
		Detail: "mode=" + mode,
	}
}

// validateResources walks the seeded resource list and flags any Broker
// resource missing policy.connect.allowed_return_urls — the misconfig that
// shipped in the demo and 100%-fails the documented quickstart.
func validateResources(cfg Config) FeatureCheck {
	const name = "resources(seeded)"
	if len(cfg.Resources) == 0 {
		return FeatureCheck{
			Name:   name,
			Status: FeatureDisabled,
			Detail: "none configured",
		}
	}
	var bad []string
	for _, r := range cfg.Resources {
		if strings.EqualFold(r.BackendKind, "broker") && len(r.Policy.Connect.AllowedReturnURLs) == 0 {
			bad = append(bad, r.Slug)
		}
	}
	if len(bad) > 0 {
		return FeatureCheck{
			Name:        name,
			Status:      FeatureMisconfigured,
			MissingKey:  "resources[].policy.connect.allowed_return_urls",
			Remediation: fmt.Sprintf("set policy.connect.allowed_return_urls on broker resources: %s", strings.Join(bad, ", ")),
		}
	}
	return FeatureCheck{
		Name:   name,
		Status: FeatureEnabled,
		Detail: fmt.Sprintf("%d ok", len(cfg.Resources)),
	}
}

// validateXAA reports the cross-app-access block. Report-only by design:
// every combination below is a legitimate deployment.
func validateXAA(cfg Config) FeatureCheck {
	const name = "xaa"
	if !cfg.XAA.Enabled {
		// The chart defaults xaa.enabled to false, so require_resource is
		// easy to set alone; say it is inert rather than only "disabled".
		detail := "xaa.enabled=false"
		if cfg.XAA.RequireResource {
			detail += " (require_resource=true has no effect)"
		}
		return FeatureCheck{
			Name:   name,
			Status: FeatureDisabled,
			Detail: detail,
		}
	}

	if !cfg.XAA.RequireResource {
		return FeatureCheck{
			Name:   name,
			Status: FeatureEnabled,
			Detail: "require_resource=false",
		}
	}

	// Only entries with a uri can satisfy the flag — enforcement matches on
	// Resource.URI and nothing requires the key.
	withURI := 0
	for _, r := range cfg.Resources {
		if r.URI != "" {
			withURI++
		}
	}
	if withURI == 0 {
		// Not a failure: enforcement reads the runtime catalog, so a
		// deployment seeded through the admin API is fine with none here.
		detail := "require_resource=true, no resources with a uri seeded in config"
		if len(cfg.Resources) > 0 {
			detail += fmt.Sprintf(" (%d seeded without one)", len(cfg.Resources))
		}
		return FeatureCheck{
			Name:   name,
			Status: FeatureEnabled,
			Detail: detail + " (the runtime catalog may still be populated via POST /admin/resources)",
		}
	}
	return FeatureCheck{
		Name:   name,
		Status: FeatureEnabled,
		Detail: fmt.Sprintf("require_resource=true, %d resource(s) with a uri seeded", withURI),
	}
}

// FormatReport renders the per-feature checks as a single padded text
// block ready for an Info-level startup log line. The output is stable —
// columns align, names sort in declaration order.
func FormatReport(checks []FeatureCheck) string {
	if len(checks) == 0 {
		return ""
	}
	const header = "=== authserver feature self-check ==="
	const footer = "======================================"

	maxName := 0
	maxStatus := 0
	for _, c := range checks {
		if n := len(c.Name); n > maxName {
			maxName = n
		}
		if n := len(c.Status.String()); n > maxStatus {
			maxStatus = n
		}
	}

	var b strings.Builder
	b.WriteString(header)
	b.WriteByte('\n')
	for _, c := range checks {
		fmt.Fprintf(&b, "  %-*s  %-*s  %s\n", maxName, c.Name, maxStatus, c.Status, c.Detail)
	}
	b.WriteString(footer)
	return b.String()
}

// MisconfiguredChecks returns the subset of checks with status
// FeatureMisconfigured, preserving order. Convenience for the boot path:
// if the slice is non-empty, the AS must exit non-zero with a fatal log
// block built from these entries.
func MisconfiguredChecks(checks []FeatureCheck) []FeatureCheck {
	var bad []FeatureCheck
	for _, c := range checks {
		if c.Status == FeatureMisconfigured {
			bad = append(bad, c)
		}
	}
	return bad
}

// FormatMisconfiguredReport renders the fatal-log block listing every
// missing key + remediation. The output is intentionally verbose so the
// operator's first read of the log explains exactly what to fix.
func FormatMisconfiguredReport(bad []FeatureCheck) string {
	if len(bad) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("authserver boot aborted: required configuration is missing or invalid")
	b.WriteByte('\n')
	for _, c := range bad {
		fmt.Fprintf(&b, "  - %s: %s\n", c.Name, c.MissingKey)
		if c.Remediation != "" {
			fmt.Fprintf(&b, "      remediation: %s\n", c.Remediation)
		}
	}
	b.WriteString("set the missing keys and restart the server.")
	return b.String()
}

// scopeTokenCharset is the RFC 6749 §3.3 scope-token production:
// 1*( %x21 / %x23-5B / %x5D-7E ) — printable ASCII minus space, quote and
// backslash.
func validScopeToken(tok string) bool {
	if tok == "" {
		return false
	}
	for _, r := range tok {
		switch {
		case r == 0x21:
		case r >= 0x23 && r <= 0x5B:
		case r >= 0x5D && r <= 0x7E:
		default:
			return false
		}
	}
	return true
}

// validateDefaultClientScope checks that oauth.default_client_scope parses into
// usable scope tokens.
//
// Nothing else validates it: the field is optional, so Validate() lets any
// string through, and the value is stamped onto clients verbatim. A malformed
// value therefore fails silently and late — every client registered afterwards
// is refused at /oauth/authorize, while the startup warning and the admin
// notice stay quiet because they only fire when the value is *empty*.
//
// The failure this is really aimed at is a comma-separated list. It is the
// natural guess for an env var, and OAuth scope is space-separated, so
// "a,b" parses as the single token "a,b" and matches no catalog entry. A comma
// is legal in a scope token per the charset above, which is exactly why the
// charset check alone would not catch it.
func validateDefaultClientScope(cfg Config) FeatureCheck {
	const name = "oauth.default_client_scope"
	value := cfg.OAuth.DefaultClientScope
	if value == "" {
		// Supported: clients are then created without a ceiling, which
		// AuthorizeService leaves unenforced until v0.3.0. The startup warning
		// covers this case.
		return FeatureCheck{Name: name, Status: FeatureDisabled, Detail: "not set"}
	}

	for _, tok := range strings.Fields(value) {
		// A comma is inside the charset checked below, so this is a judgement
		// about intent rather than validity: OAuth scope is space-separated,
		// and a comma is the near-universal way to get that wrong. Only a
		// comma — a semicolon is legal, far less plausible as a mistyped
		// separator, and refusing it would be this check inventing a rule.
		if strings.Contains(tok, ",") {
			return FeatureCheck{
				Name:       name,
				Status:     FeatureMisconfigured,
				MissingKey: "oauth.default_client_scope",
				Remediation: fmt.Sprintf("scope %q contains a comma: OAuth scope is "+
					"space-separated (RFC 6749 3.3), so this parses as one token and will match "+
					"no registered scope. Write them separated by spaces. A comma is a legal "+
					"scope character, so if this one is deliberate the value cannot be "+
					"expressed here — use the admin API to set that client's scope directly", tok),
			}
		}
		if !validScopeToken(tok) {
			return FeatureCheck{
				Name:       name,
				Status:     FeatureMisconfigured,
				MissingKey: "oauth.default_client_scope",
				Remediation: fmt.Sprintf("scope %q is not a valid scope token: RFC 6749 3.3 allows "+
					"printable ASCII except space, double quote and backslash", tok),
			}
		}
	}

	return FeatureCheck{
		Name:   name,
		Status: FeatureEnabled,
		Detail: fmt.Sprintf("%d scope(s)", len(strings.Fields(value))),
	}
}
