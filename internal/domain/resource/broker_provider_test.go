package resource_test

import (
	"testing"

	"github.com/authplane/authserver/internal/domain/resource"
)

func TestProtocol_Constants(t *testing.T) {
	cases := map[resource.Protocol]string{
		resource.ProtocolOAuth:          "oauth",
		resource.ProtocolAPIKey:         "api_key",
		resource.ProtocolServiceAccount: "service_account",
	}
	for p, want := range cases {
		if string(p) != want {
			t.Errorf("Protocol %q does not equal wire string %q", p, want)
		}
	}
}

func TestBrokerProvider_ZeroValueRoundTrip(t *testing.T) {
	bp := resource.BrokerProvider{
		ID:          "bp-1",
		Slug:        "google-workspace",
		DisplayName: "Google Workspace",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"client_id":"x"}`),
	}
	if bp.ID != "bp-1" {
		t.Errorf("ID round-trip failed: %q", bp.ID)
	}
	if bp.Slug != "google-workspace" {
		t.Errorf("Slug round-trip failed: %q", bp.Slug)
	}
	if bp.DisplayName != "Google Workspace" {
		t.Errorf("DisplayName round-trip failed: %q", bp.DisplayName)
	}
	if bp.Protocol != resource.ProtocolOAuth {
		t.Errorf("Protocol round-trip failed: %q", bp.Protocol)
	}
	if string(bp.ConfigData) != `{"client_id":"x"}` {
		t.Errorf("ConfigData round-trip failed: %q", bp.ConfigData)
	}
}
