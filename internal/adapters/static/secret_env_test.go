package static_test

import (
	"context"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/adapters/static"
)

// TestEnvSecrets_Resolve_AllowedName_ReturnsValue mirrors
// TestEnvSecretResolver_AllowedName_ReturnsValue from cmd/authserver/secret_resolver_test.go.
func TestEnvSecrets_Resolve_AllowedName_ReturnsValue(t *testing.T) {
	t.Setenv("CONNECTOR_X", "s3cr3t")

	s := static.NewEnvSecrets()
	got, err := s.Resolve(context.Background(), "CONNECTOR_X")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "s3cr3t" {
		t.Errorf("got %q, want %q", got, "s3cr3t")
	}
}

// TestEnvSecrets_Resolve_VaultPrefix mirrors
// TestEnvSecretResolver_VaultPrefix_Allowed from cmd/authserver/secret_resolver_test.go.
func TestEnvSecrets_Resolve_VaultPrefix(t *testing.T) {
	t.Setenv("AUTHPLANE_VAULT_SA_KEY", "pem-bytes")

	s := static.NewEnvSecrets()
	got, err := s.Resolve(context.Background(), "AUTHPLANE_VAULT_SA_KEY")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "pem-bytes" {
		t.Errorf("got %q, want %q", got, "pem-bytes")
	}
}

// TestEnvSecrets_Resolve_AllowedButUnset mirrors
// TestEnvSecretResolver_AllowedButUnset_ReturnsEmpty from cmd/authserver/secret_resolver_test.go.
func TestEnvSecrets_Resolve_AllowedButUnset(t *testing.T) {
	s := static.NewEnvSecrets()
	got, err := s.Resolve(context.Background(), "CONNECTOR_DEFINITELY_UNSET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

// TestEnvSecrets_Resolve_Disallowed_PATH mirrors
// TestEnvSecretResolver_DisallowedName_Rejected from cmd/authserver/secret_resolver_test.go.
func TestEnvSecrets_Resolve_Disallowed_PATH(t *testing.T) {
	s := static.NewEnvSecrets()
	got, err := s.Resolve(context.Background(), "PATH")
	if err == nil {
		t.Fatal("expected an error for a disallowed reference, got nil")
	}
	if got != "" {
		t.Errorf("disallowed reference leaked a value: %q", got)
	}
	if !strings.Contains(err.Error(), "PATH") {
		t.Errorf("error should name the rejected reference, got: %v", err)
	}
}

// TestEnvSecrets_Resolve_LowercaseRejected mirrors
// TestEnvSecretResolver_LowercaseName_Rejected from cmd/authserver/secret_resolver_test.go.
func TestEnvSecrets_Resolve_LowercaseRejected(t *testing.T) {
	t.Setenv("CONNECTOR_CLIENT_SECRET", "s3cr3t")

	s := static.NewEnvSecrets()
	if _, err := s.Resolve(context.Background(), "connector-client-secret"); err == nil {
		t.Error("expected an error for a non-conforming reference, got nil")
	}
}
