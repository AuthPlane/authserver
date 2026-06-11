package oauth

import (
	"encoding/json"
	"fmt"
)

// Response format identifiers used in configData.ResponseFormat. The wire
// shape returned by the upstream token endpoint determines how HandleCallback
// and Vend parse the response body. "standard" is the OAuth 2.0 JSON shape
// per RFC 6749 §5.1; "form" is application/x-www-form-urlencoded as some
// upstreams (e.g. GitHub's legacy /login/oauth/access_token without an
// Accept: application/json header) emit.
const (
	responseFormatStandard = "standard"
	responseFormatForm     = "form"
)

// configData is the JSON shape persisted in broker_providers.config_data for
// providers using the oauth protocol. It is owned end-to-end by this adapter:
// the core code never parses it. See the resource-unification design
// and the architecture doc
//
// ExtraAuthParams preserves arbitrary upstream-required authorize
// parameters (Google's access_type=offline, etc.) round-trip from
// configuration to the authorize URL. Reserved OAuth keys are dropped at
// build time as defense-in-depth (see scope_mapping.go callers).
type configData struct {
	ClientID        string            `json:"client_id"`
	ClientSecretEnv string            `json:"client_secret_env"`
	AuthorizeURL    string            `json:"authorize_url"`
	TokenURL        string            `json:"token_url"`
	RevokeURL       string            `json:"revoke_url,omitempty"`
	ResponseFormat  string            `json:"response_format,omitempty"`
	ExtraAuthParams map[string]string `json:"extra_auth_params,omitempty"`
}

// parseConfigData unmarshals the raw bytes from broker_providers.config_data
// into configData. It validates the minimum fields the adapter needs to
// build the authorize URL and call the token endpoint. Anything richer
// (env-var-name shape, URL scheme, etc.) is enforced by the admin service
// when a provider is created or updated; this is a runtime sanity check.
func parseConfigData(raw []byte) (configData, error) {
	if len(raw) == 0 {
		return configData{}, fmt.Errorf("oauth config_data: empty")
	}
	var cfg configData
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return configData{}, fmt.Errorf("oauth config_data: %w", err)
	}
	if cfg.ClientID == "" {
		return configData{}, fmt.Errorf("oauth config_data: client_id is required")
	}
	if cfg.AuthorizeURL == "" {
		return configData{}, fmt.Errorf("oauth config_data: authorize_url is required")
	}
	if cfg.TokenURL == "" {
		return configData{}, fmt.Errorf("oauth config_data: token_url is required")
	}
	if cfg.ResponseFormat == "" {
		cfg.ResponseFormat = responseFormatStandard
	}
	switch cfg.ResponseFormat {
	case responseFormatStandard, responseFormatForm:
	default:
		return configData{}, fmt.Errorf("oauth config_data: unsupported response_format %q (want %q or %q)",
			cfg.ResponseFormat, responseFormatStandard, responseFormatForm)
	}
	return cfg, nil
}
