package serviceaccount

import (
	"encoding/json"
	"fmt"
)

// credentialData is the JSON shape persisted in broker_grants.credential_data
// for providers using the service_account protocol. Unlike oauth or api_key,
// this row carries no per-user secret — the SA private key is held by the
// operator and referenced from configData.SAKeyEnv. The only per-user state
// is the upstream subject the AS impersonates.
//
// Per the resource-unification design the AS does not cache the
// upstream access token — Vend signs a fresh assertion and exchanges it
// at the upstream's token endpoint on every call.
type credentialData struct {
	ImpersonateSub string `json:"impersonate_sub"`
}

// parseCredential unmarshals plaintext credential bytes into credentialData.
// An empty payload is treated as missing rather than zero-value so callers
// can distinguish "no upstream credential persisted yet" from "the operator
// configured an empty impersonation subject."
func parseCredential(raw []byte) (credentialData, error) {
	if len(raw) == 0 {
		return credentialData{}, fmt.Errorf("service_account credential: empty")
	}
	var cred credentialData
	if err := json.Unmarshal(raw, &cred); err != nil {
		return credentialData{}, fmt.Errorf("service_account credential: %w", err)
	}
	if cred.ImpersonateSub == "" {
		return credentialData{}, fmt.Errorf("service_account credential: impersonate_sub is required")
	}
	return cred, nil
}

// marshalCredential returns the JSON bytes for the given impersonation sub,
// shaped per credentialData. Used by tests and by the connect flow that
// persists the user's upstream identity at first vend.
func marshalCredential(impersonateSub string) ([]byte, error) {
	return json.Marshal(credentialData{ImpersonateSub: impersonateSub})
}
