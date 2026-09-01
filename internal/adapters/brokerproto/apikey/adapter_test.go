package apikey

import (
	"context"
	"errors"
	"testing"

	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/output"
)

// stubSecretResolver satisfies the SecretResolver interface even though the
// adapter never invokes it. Present to mirror the oauth adapter's test rig
// and to assert at compile time that the interface still type-checks.
type stubSecretResolver struct{}

func (stubSecretResolver) Resolve(context.Context, output.SecretSource) (string, error) {
	return "", nil
}

func mustProvider() *resource.BrokerProvider {
	return &resource.BrokerProvider{
		ID:       "P-apikey",
		Slug:     "openai-default",
		Protocol: resource.ProtocolAPIKey,
		ConfigData: []byte(`{
			"header_name": "Authorization",
			"header_prefix": "Bearer ",
			"issuance_instructions_url": "https://platform.openai.com/api-keys"
		}`),
	}
}

func mustResource() *resource.Resource {
	return &resource.Resource{
		ID:               "R-openai",
		Slug:             "openai",
		BackendKind:      resource.BackendBroker,
		BrokerProviderID: "P-apikey",
	}
}

// --- Name() -----------------------------------------------------------------

func TestAPIKeyAdapter_Name_ReturnsApiKey(t *testing.T) {
	a := New(stubSecretResolver{})
	if got := a.Name(); got != "api_key" {
		t.Fatalf("Name() = %q, want api_key", got)
	}
}

// --- BuildConnectURL --------------------------------------------------------

func TestAPIKeyAdapter_BuildConnectURL_ReturnsErrNoConnectStep(t *testing.T) {
	// api_key has no per-user upstream consent flow. The orchestration layer
	// compares with errors.Is and renders a paste-the-key form.
	a := New(stubSecretResolver{})
	prov := mustProvider()
	r := mustResource()

	authURL, pending, err := a.BuildConnectURL(context.Background(), prov, r,
		"user-1", "https://app.example.com/post-connect", "https://as.example.com/connect/api-key/callback", []string{"any"})
	if !errors.Is(err, output.ErrNoConnectStep) {
		t.Fatalf("err = %v, want output.ErrNoConnectStep", err)
	}
	if authURL != "" {
		t.Errorf("authURL = %q, want empty when no connect step", authURL)
	}
	if pending != nil {
		t.Errorf("pending = %+v, want nil when no connect step", pending)
	}
}

// --- HandleCallback ---------------------------------------------------------

func TestAPIKeyAdapter_HandleCallback_ReturnsErrNoConnectStep(t *testing.T) {
	a := New(stubSecretResolver{})
	prov := mustProvider()
	r := mustResource()

	credBytes, granted, err := a.HandleCallback(context.Background(), prov, r,
		"unused-code", "https://as.example.com/connect/api-key/callback", &resource.ConnectPendingState{ID: "unused"})
	if !errors.Is(err, output.ErrNoConnectStep) {
		t.Fatalf("err = %v, want output.ErrNoConnectStep", err)
	}
	if credBytes != nil {
		t.Errorf("credBytes = %v, want nil when no connect step", credBytes)
	}
	if granted != nil {
		t.Errorf("scopesGranted = %v, want nil when no connect step", granted)
	}
}

// --- Vend -------------------------------------------------------------------

func TestAPIKeyAdapter_Vend_ReturnsStoredKey(t *testing.T) {
	a := New(stubSecretResolver{})
	prov := mustProvider()
	r := mustResource()
	cred, err := marshalCredential("sk-abc")
	if err != nil {
		t.Fatalf("marshalCredential: %v", err)
	}

	access, _, _, err := a.Vend(context.Background(), prov, r, cred, []string{"ignored"})
	if err != nil {
		t.Fatalf("Vend: %v", err)
	}
	if access != "sk-abc" {
		t.Errorf("access token = %q, want sk-abc", access)
	}
}

func TestAPIKeyAdapter_Vend_ExpiresInZero(t *testing.T) {
	// API keys are long-lived; expiresIn=0 signals "no AS-known lifetime"
	// to BrokerIssuer per the resource-unification design
	a := New(stubSecretResolver{})
	prov := mustProvider()
	r := mustResource()
	cred, _ := marshalCredential("sk-anthropic-xyz")

	_, expiresIn, _, err := a.Vend(context.Background(), prov, r, cred, nil)
	if err != nil {
		t.Fatalf("Vend: %v", err)
	}
	if expiresIn != 0 {
		t.Errorf("expiresIn = %d, want 0 (non-expiring marker)", expiresIn)
	}
}

func TestAPIKeyAdapter_Vend_UpdatedCredentialNil(t *testing.T) {
	// API keys never rotate from the AS's perspective. updatedCredential
	// must be nil so BrokerIssuer skips the optimistic-lock UPDATE.
	a := New(stubSecretResolver{})
	prov := mustProvider()
	r := mustResource()
	cred, _ := marshalCredential("pat_github_long_lived")

	_, _, updated, err := a.Vend(context.Background(), prov, r, cred, nil)
	if err != nil {
		t.Fatalf("Vend: %v", err)
	}
	if updated != nil {
		t.Errorf("updatedCredential = %v, want nil (api_key never rotates)", updated)
	}
}

// --- Revoke -----------------------------------------------------------------

func TestAPIKeyAdapter_Revoke_NoOpReturnsNil(t *testing.T) {
	// No upstream revoke API for user-issued PATs. Adapter returns nil so
	// BrokerIssuer treats the local revocation (broker_grants.revoked_at)
	// as authoritative.
	a := New(stubSecretResolver{})
	prov := mustProvider()
	cred, _ := marshalCredential("sk-revoke-target")

	if err := a.Revoke(context.Background(), prov, cred); err != nil {
		t.Errorf("Revoke = %v, want nil (no-op)", err)
	}
}
