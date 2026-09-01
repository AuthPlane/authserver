package static

import (
	"context"
	"testing"
)

// The CONNECTOR_*/AUTHPLANE_VAULT_* allowlist stops a config row from naming an
// arbitrary process env var. v0.1.x predates that rule and documented names
// like OIDC_CLIENT_SECRET, so refs carried over from the deprecated
// oidc.client_secret_env key get a narrow exemption. Everything else must stay
// rejected — that is the security property these tests pin.

func TestEnvSecrets_RejectsUnprefixedRefByDefault(t *testing.T) {
	t.Setenv("OIDC_CLIENT_SECRET", "value")

	if _, err := NewEnvSecrets().Resolve(context.Background(), "OIDC_CLIENT_SECRET"); err == nil {
		t.Fatal("an unprefixed ref must be rejected when it is not legacy-sourced")
	}
}

func TestEnvSecrets_AdmitsLegacyRef(t *testing.T) {
	t.Setenv("OIDC_CLIENT_SECRET", "value")

	got, err := NewEnvSecrets("OIDC_CLIENT_SECRET").Resolve(context.Background(), "OIDC_CLIENT_SECRET")
	if err != nil {
		t.Fatalf("a legacy-sourced ref must resolve, got: %v", err)
	}
	if got != "value" {
		t.Errorf("Resolve = %q, want %q", got, "value")
	}
}

// The exemption must cover only the exact refs handed in, not every unprefixed
// name, so one legacy OIDC key cannot open the door to reading PATH or AWS_*.
func TestEnvSecrets_LegacyExemptionIsScopedToNamedRefs(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "should-not-be-readable")

	if _, err := NewEnvSecrets("OIDC_CLIENT_SECRET").Resolve(context.Background(), "AWS_SECRET_ACCESS_KEY"); err == nil {
		t.Fatal("the legacy exemption must not admit refs it was not given")
	}
}

func TestEnvSecrets_EmptyLegacyRefIsIgnored(t *testing.T) {
	if _, err := NewEnvSecrets("").Resolve(context.Background(), "PATH"); err == nil {
		t.Fatal("an empty legacy ref must not disable the allowlist")
	}
}

func TestEnvSecrets_AllowlistedRefStillResolves(t *testing.T) {
	t.Setenv("CONNECTOR_GOOGLE_SECRET", "google-value")

	got, err := NewEnvSecrets().Resolve(context.Background(), "CONNECTOR_GOOGLE_SECRET")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "google-value" {
		t.Errorf("Resolve = %q, want %q", got, "google-value")
	}
}
