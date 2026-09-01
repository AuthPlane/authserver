package static_test

import (
	"context"
	"testing"

	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/ports/output"
)

// TestOIDCConfigProvider_ProjectsConfig: the provider is a pure passthrough — it
// returns the output.OIDCConfig it was built with, verbatim, with no I/O.
// ClientSecret and ClientSecretRef are mutually exclusive (config validation
// rejects both), so exactly one is set on the config it transports; the provider
// applies no precedence.
func TestOIDCConfigProvider_ProjectsConfig(t *testing.T) {
	cfg := output.OIDCConfig{
		Issuer:             "https://idp.example.com",
		ClientID:           "client-1",
		RedirectURI:        "https://app.example.com/callback",
		Scopes:             []string{"openid", "email"},
		IncludeGroupsScope: true,
		ConnectorID:        "okta",
		ClientSecret:       []byte("at-rest-bytes"),
	}
	p := static.NewOIDCConfigProvider(cfg)

	got, err := p.Config(context.Background())
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if got.Issuer != cfg.Issuer || got.ClientID != cfg.ClientID ||
		got.RedirectURI != cfg.RedirectURI || !got.IncludeGroupsScope ||
		got.ConnectorID != cfg.ConnectorID {
		t.Fatalf("unexpected projection: %+v", got)
	}
	if len(got.Scopes) != 2 || got.Scopes[0] != "openid" || got.Scopes[1] != "email" {
		t.Fatalf("unexpected scopes: %v", got.Scopes)
	}
	if string(got.ClientSecret) != "at-rest-bytes" {
		t.Errorf("ClientSecret = %q, want at-rest-bytes", string(got.ClientSecret))
	}
	if got.JWKS != nil {
		t.Fatalf("JWKS should be nil (discovered on first use), got %d bytes", len(got.JWKS))
	}
}

// TestOIDCConfigProvider_CarriesRefVerbatim: a ref-only DTO is projected as-is.
func TestOIDCConfigProvider_CarriesRefVerbatim(t *testing.T) {
	p := static.NewOIDCConfigProvider(output.OIDCConfig{ClientSecretRef: "CONNECTOR_OIDC_SECRET"})

	got, err := p.Config(context.Background())
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if got.ClientSecretRef != "CONNECTOR_OIDC_SECRET" {
		t.Errorf("ClientSecretRef = %q, want CONNECTOR_OIDC_SECRET", got.ClientSecretRef)
	}
	if len(got.ClientSecret) != 0 {
		t.Errorf("ClientSecret should be empty when only a ref is set, got %d bytes", len(got.ClientSecret))
	}
}

func TestOIDCConfigProvider_RoundTripsEnabled(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		p := static.NewOIDCConfigProvider(output.OIDCConfig{Enabled: enabled, Issuer: "https://idp.example"})
		got, err := p.Config(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Enabled != enabled {
			t.Fatalf("Enabled: got %v, want %v", got.Enabled, enabled)
		}
	}
}
