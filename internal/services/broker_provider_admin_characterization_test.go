// Characterization tests for broker-provider secret handling.
//
// These tests pin the CURRENT behavior of BrokerProviderAdminService and are
// FROZEN: if a later refactor phase causes one to fail, fix the production
// code, not these assertions.
//
// One sanctioned exception: TestCharacterization_Create_RejectsRawClientSecret
// asserts the env backend's "inline values" message rather than the original
// "use the *_ref convention" guard message. The rejection path moved (guard →
// backend) as a deliberate behavior change; the test still pins that a raw client
// secret is rejected at Create, only the message/source changed.
package services

import (
	"bytes"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/domain/resource"
)

// TestCharacterization_Create_RejectsRawClientSecret pins that Create rejects a
// literal client_secret value in config_data. A raw value in a routed secret
// field is forwarded to the SecretEncoder, which (for the env backend) rejects it
// because it stores no inline values — so the rejection comes from the backend,
// not the raw-secret guard.
func TestCharacterization_Create_RejectsRawClientSecret(t *testing.T) {
	env := newBrokerProviderAdminTestEnv()
	p := &resource.BrokerProvider{
		Slug:        "github",
		DisplayName: "GitHub",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"client_id":"x","client_secret":"literal-secret-value"}`),
	}
	err := env.svc.Create(t.Context(), p)
	if err == nil {
		t.Fatal("expected rejection of literal client_secret, got nil")
	}
	if !strings.Contains(err.Error(), "inline values") {
		t.Errorf("raw client_secret should be rejected by the env backend, got: %v", err)
	}
}

// TestCharacterization_Create_PersistsConfigDataVerbatim pins that Create
// stores config_data bytes exactly as supplied and GetBySlug returns them
// unchanged.
func TestCharacterization_Create_PersistsConfigDataVerbatim(t *testing.T) {
	env := newBrokerProviderAdminTestEnv()
	input := []byte(`{"client_id":"x","client_secret_ref":"CONNECTOR_GH","authorize_url":"https://a","token_url":"https://t"}`)
	p := &resource.BrokerProvider{
		Slug:        "github-roundtrip",
		DisplayName: "GitHub RT",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  input,
	}
	if err := env.svc.Create(t.Context(), p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := env.svc.GetBySlug(t.Context(), p.Slug)
	if err != nil {
		t.Fatalf("GetBySlug: %v", err)
	}
	if !bytes.Equal(got.ConfigData, input) {
		t.Errorf("config_data round-trip mismatch:\n  got  %s\n  want %s", got.ConfigData, input)
	}
}

// TestCharacterization_Create_AcceptsProviderWithoutSecretRef pins that
// Create does NOT reject an OAuth provider whose config_data carries no
// secret reference. The adapter reports missing secrets lazily at vend time;
// the admin service must not enforce this at creation.
func TestCharacterization_Create_AcceptsProviderWithoutSecretRef(t *testing.T) {
	env := newBrokerProviderAdminTestEnv()
	p := &resource.BrokerProvider{
		Slug:        "github-nosecret",
		DisplayName: "GitHub No-Secret",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"client_id":"x"}`),
	}
	if err := env.svc.Create(t.Context(), p); err != nil {
		t.Errorf("Create with no secret ref should be accepted, got: %v", err)
	}
}
