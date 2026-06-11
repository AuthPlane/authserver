package apikey

import (
	"encoding/json"
	"fmt"
)

// configData is the JSON shape persisted in broker_providers.config_data for
// providers using the api_key protocol. It is owned end-to-end by this
// adapter: the core code never parses it. See
// the resource-unification design and the architecture doc
//
// HeaderName and HeaderPrefix are descriptive metadata advertised to the
// resource server / MCP via the connect-result UX so the MCP knows how to
// format the upstream call (e.g. "Authorization: Bearer <key>" vs
// "X-API-Key: <key>"). The adapter itself does not send HTTP — Vend just
// returns the stored key.
type configData struct {
	HeaderName              string `json:"header_name"`
	HeaderPrefix            string `json:"header_prefix,omitempty"`
	IssuanceInstructionsURL string `json:"issuance_instructions_url,omitempty"`
}

// parseConfigData unmarshals the raw bytes from broker_providers.config_data
// into configData. It validates the minimum field the adapter advertises to
// downstream consumers. Anything richer (URL scheme on
// IssuanceInstructionsURL, header-name shape) is enforced by the admin
// service when a provider is created or updated; this is a runtime sanity
// check.
func parseConfigData(raw []byte) (configData, error) {
	if len(raw) == 0 {
		return configData{}, fmt.Errorf("api_key config_data: empty")
	}
	var cfg configData
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return configData{}, fmt.Errorf("api_key config_data: %w", err)
	}
	if cfg.HeaderName == "" {
		return configData{}, fmt.Errorf("api_key config_data: header_name is required")
	}
	return cfg, nil
}
