package oauth

import (
	"encoding/json"
	"fmt"
)

// credentialData is the JSON shape persisted (encrypted at rest by
// BrokerIssuer / DataEncryptor) in broker_grants.credential_data for
// providers using the oauth protocol. The adapter receives plaintext
// bytes at the BrokerProtocol port boundary; the storage layer
// handles encryption.
//
// Per the resource-unification design and §5.3 the AS does not cache
// the upstream access token — only the long-lived refresh token survives
// across vends. Each Vend exchanges this refresh for a fresh access token.
type credentialData struct {
	RefreshToken string `json:"refresh_token"`
}

// parseCredential unmarshals plaintext credential bytes into credentialData.
// An empty payload is treated as missing rather than zero-value so callers
// can distinguish "no upstream credential persisted yet" from "upstream
// returned an empty refresh token."
func parseCredential(raw []byte) (credentialData, error) {
	if len(raw) == 0 {
		return credentialData{}, fmt.Errorf("oauth credential: empty")
	}
	var cred credentialData
	if err := json.Unmarshal(raw, &cred); err != nil {
		return credentialData{}, fmt.Errorf("oauth credential: %w", err)
	}
	if cred.RefreshToken == "" {
		return credentialData{}, fmt.Errorf("oauth credential: refresh_token is required")
	}
	return cred, nil
}

// marshalCredential returns the JSON bytes for the given refresh token,
// shaped per credentialData. Used by HandleCallback (initial persist) and
// Vend (rotation persist).
func marshalCredential(refresh string) ([]byte, error) {
	return json.Marshal(credentialData{RefreshToken: refresh})
}
