package apikey

import (
	"encoding/json"
	"fmt"
)

// credentialData is the JSON shape persisted (encrypted at rest by
// BrokerIssuer / DataEncryptor) in broker_grants.credential_data for
// providers using the api_key protocol. The adapter receives plaintext
// bytes at the BrokerProtocol port boundary; the storage layer
// handles encryption.
//
// Per the resource-unification design the api_key adapter persists
// only the long-lived API key the user pasted at connect time. Each Vend
// returns it verbatim — there is no upstream call.
type credentialData struct {
	APIKey string `json:"api_key"`
}

// parseCredential unmarshals plaintext credential bytes into credentialData.
// An empty payload is treated as missing rather than zero-value so callers
// can distinguish "no upstream credential persisted yet" from "the user
// pasted an empty string."
func parseCredential(raw []byte) (credentialData, error) {
	if len(raw) == 0 {
		return credentialData{}, fmt.Errorf("api_key credential: empty")
	}
	var cred credentialData
	if err := json.Unmarshal(raw, &cred); err != nil {
		return credentialData{}, fmt.Errorf("api_key credential: %w", err)
	}
	if cred.APIKey == "" {
		return credentialData{}, fmt.Errorf("api_key credential: api_key is required")
	}
	return cred, nil
}

// marshalCredential returns the JSON bytes for the given API key, shaped per
// credentialData. Used by tests and by the connect-paste flow that
// lands the user-supplied key on the broker_grants table.
func marshalCredential(apiKey string) ([]byte, error) {
	return json.Marshal(credentialData{APIKey: apiKey})
}
