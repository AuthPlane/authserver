package serviceaccount

import (
	"encoding/json"
	"fmt"
)

// Algorithm identifiers used in configData.Algorithm. The wire-protocol
// signing algorithm for the assertion. RS256 is the default — it matches
// every Google Workspace SA key (PKCS#8 RSA) and most Atlassian/Forge SAs.
// ES256 covers PKCS#8 or SEC1 EC keys (Cloudflare, GitHub apps).
const (
	algorithmRS256 = "RS256"
	algorithmES256 = "ES256"
)

// defaultTokenTTLSeconds is the assertion `exp - iat` window when the
// provider does not configure one. Chosen to match Google's "exp ≤ 1 hour
// from iat" cap so an out-of-the-box SA configuration validates against
// the strictest known upstream.
const defaultTokenTTLSeconds = 3600

// minTokenTTLSeconds rejects unreasonably short TTLs that would fail
// upstream verification on minor clock skew (audit M5). 30s is the
// industry-typical floor for clock-tolerance margin.
const minTokenTTLSeconds = 30

// maxTokenTTLSeconds rejects unreasonably long TTLs. Most upstreams
// (Google, Atlassian) cap assertion lifetime at 1h; oversized values
// will fail verification or, worse, get silently truncated. Matches
// defaultTokenTTLSeconds — operators wanting longer lifetimes will hit
// upstream caps anyway.
const maxTokenTTLSeconds = 3600

// configData is the JSON shape persisted in broker_providers.config_data
// for providers using the service_account protocol. It is owned end-to-end
// by this adapter: the core code never parses it. See
// the resource-unification design and the architecture doc
//
// The SA private key is referenced by env-var name (SAKeyEnv), not stored
// inline. The KeyStore port handles AS-issued (mint) signing keys; SA keys
// are upstream credentials and live in the operator's process environment.
type configData struct {
	TokenURL        string `json:"token_url"`
	SAEmail         string `json:"sa_email"`
	SAKeyEnv        string `json:"sa_key_env"`
	TokenTTLSeconds int    `json:"token_ttl_seconds,omitempty"`
	Algorithm       string `json:"algorithm,omitempty"`
}

// parseConfigData unmarshals the raw bytes from broker_providers.config_data
// into configData. It validates the minimum fields the adapter needs to
// build the JWT assertion and call the token endpoint; richer checks
// (URL scheme, env-var-name shape) live elsewhere — admin-side at write,
// resolveSAKey at read.
func parseConfigData(raw []byte) (configData, error) {
	if len(raw) == 0 {
		return configData{}, fmt.Errorf("service_account config_data: empty")
	}
	var cfg configData
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return configData{}, fmt.Errorf("service_account config_data: %w", err)
	}
	if cfg.TokenURL == "" {
		return configData{}, fmt.Errorf("service_account config_data: token_url is required")
	}
	if cfg.SAEmail == "" {
		return configData{}, fmt.Errorf("service_account config_data: sa_email is required")
	}
	if cfg.SAKeyEnv == "" {
		return configData{}, fmt.Errorf("service_account config_data: sa_key_env is required")
	}
	if cfg.Algorithm == "" {
		cfg.Algorithm = algorithmRS256
	}
	switch cfg.Algorithm {
	case algorithmRS256, algorithmES256:
	default:
		return configData{}, fmt.Errorf("service_account config_data: unsupported algorithm %q (want %q or %q)",
			cfg.Algorithm, algorithmRS256, algorithmES256)
	}
	if cfg.TokenTTLSeconds == 0 {
		cfg.TokenTTLSeconds = defaultTokenTTLSeconds
	}
	if cfg.TokenTTLSeconds < minTokenTTLSeconds || cfg.TokenTTLSeconds > maxTokenTTLSeconds {
		return configData{}, fmt.Errorf(
			"service_account config_data: token_ttl_seconds %d out of bounds [%d,%d] — "+
				"too-short values fail upstream verification on clock skew; "+
				"too-long values exceed typical 1h upstream caps",
			cfg.TokenTTLSeconds, minTokenTTLSeconds, maxTokenTTLSeconds)
	}
	return cfg, nil
}
