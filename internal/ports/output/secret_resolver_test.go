package output

import "testing"

// connector_id is optional in single-connector OSS; the OIDC ownerContext must
// fall back to a stable sentinel rather than degenerate to the bare "oidc:"
// prefix, so per-connector isolation stays meaningful and encrypt/decrypt stay
// symmetric (both build the owner through this helper).
func TestGetSecretSourceForOIDC_OwnerFallback(t *testing.T) {
	got := GetSecretSourceForOIDC(OIDCConfig{ConnectorID: ""})
	if got.Owner.Kind != OwnerKindOIDC {
		t.Errorf("Owner.Kind = %v, want OwnerKindOIDC", got.Owner.Kind)
	}
	if got.Owner.ID != "default" {
		t.Errorf("Owner.ID = %q, want \"default\" (empty connector_id fallback)", got.Owner.ID)
	}

	got = GetSecretSourceForOIDC(OIDCConfig{ConnectorID: "okta"})
	if got.Owner.ID != "okta" {
		t.Errorf("Owner.ID = %q, want \"okta\" (configured connector_id used verbatim)", got.Owner.ID)
	}
}
