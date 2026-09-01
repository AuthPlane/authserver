// Characterization tests for oauth adapter secret resolution.
package oauth

import (
	"context"
	"testing"

	"github.com/authplane/authserver/internal/domain/resource"
)

// TestCharacterization_OAuth_ResolvesClientSecretRefField pins that
// parseConfigData reads the client_secret_ref field and that the adapter
// resolves through it via resolveSecret.
func TestCharacterization_OAuth_ResolvesClientSecretRefField(t *testing.T) {
	cfg, err := parseConfigData([]byte(`{"client_id":"x","client_secret_ref":"CONNECTOR_GH","authorize_url":"https://a","token_url":"https://t"}`))
	if err != nil {
		t.Fatalf("parseConfigData: %v", err)
	}
	a := &Adapter{secretResolver: &stubSecretResolver{secret: "resolved"}}
	got, err := a.resolveSecret(context.Background(), &resource.BrokerProvider{ID: "p1"}, cfg.ClientSecretRef)
	if err != nil {
		t.Fatalf("resolveSecret: %v", err)
	}
	if got != "resolved" {
		t.Errorf("got %q, want resolved", got)
	}
}
