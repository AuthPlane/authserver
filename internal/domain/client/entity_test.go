package client

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
)

func newTestClient() *Client {
	return &Client{
		ID:                      "client-123",
		Name:                    "Test Client",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Status:                  StatusActive,
		RegistrationSource:      SourceDCR,
		IssuedAt:                time.Now().UTC(),
		UpdatedAt:               time.Now().UTC(),
	}
}

func TestClientIsPublic(t *testing.T) {
	c := newTestClient()
	if !c.IsPublic() {
		t.Error("client with no secret should be public")
	}
	c.SecretHash = "$2a$10$somebcrypthash"
	if c.IsPublic() {
		t.Error("client with secret should not be public")
	}
}

func TestClientIsActive(t *testing.T) {
	c := newTestClient()
	if !c.IsActive() {
		t.Error("new client should be active")
	}
	c.Status = StatusSuspended
	if c.IsActive() {
		t.Error("suspended client should not be active")
	}
}

func TestClientSuspend(t *testing.T) {
	c := newTestClient()
	if err := c.Suspend(); err != nil {
		t.Fatalf("Suspend active client: %v", err)
	}
	if c.Status != StatusSuspended {
		t.Errorf("status = %q, want suspended", c.Status)
	}
}

func TestClientSuspendFromSuspended(t *testing.T) {
	c := newTestClient()
	c.Status = StatusSuspended
	if err := c.Suspend(); err == nil {
		t.Error("suspending already-suspended client should fail")
	}
}

func TestClientSuspendFromRevoked(t *testing.T) {
	c := newTestClient()
	c.Status = StatusRevoked
	if err := c.Suspend(); err == nil {
		t.Error("suspending revoked client should fail")
	}
}

func TestClientRevoke(t *testing.T) {
	c := newTestClient()
	c.Revoke()
	if c.Status != StatusRevoked {
		t.Errorf("status = %q, want revoked", c.Status)
	}
}

func TestClientRevokeFromAnyState(t *testing.T) {
	for _, initial := range []Status{StatusActive, StatusSuspended, StatusRevoked} {
		c := newTestClient()
		c.Status = initial
		c.Revoke() // should not panic
		if c.Status != StatusRevoked {
			t.Errorf("Revoke from %q: status = %q, want revoked", initial, c.Status)
		}
	}
}

func TestClientReactivate(t *testing.T) {
	c := newTestClient()
	c.Status = StatusSuspended
	if err := c.Reactivate(); err != nil {
		t.Fatalf("Reactivate suspended client: %v", err)
	}
	if c.Status != StatusActive {
		t.Errorf("status = %q, want active", c.Status)
	}
}

func TestClientReactivateFromActive(t *testing.T) {
	c := newTestClient()
	if err := c.Reactivate(); err == nil {
		t.Error("reactivating active client should fail")
	}
}

func TestClientReactivateFromRevoked(t *testing.T) {
	c := newTestClient()
	c.Status = StatusRevoked
	if err := c.Reactivate(); err == nil {
		t.Error("reactivating revoked client should fail")
	}
}

func TestClientHasRedirectURI(t *testing.T) {
	c := newTestClient()
	if !c.HasRedirectURI("https://app.example.com/callback") {
		t.Error("should match registered URI")
	}
	if c.HasRedirectURI("https://app.example.com/callback/") {
		t.Error("should not match with trailing slash (exact match)")
	}
	if c.HasRedirectURI("https://evil.com/callback") {
		t.Error("should not match unregistered URI")
	}
}

func TestHasRedirectURI_LoopbackPortIgnored(t *testing.T) {
	tests := []struct {
		name       string
		registered string
		requested  string
		want       bool
	}{
		// Loopback — port flexibility (RFC 8252 §7.3)
		{"localhost dynamic port", "http://localhost/callback", "http://localhost:57292/callback", true},
		{"localhost registered with port", "http://localhost:8080/callback", "http://localhost:9090/callback", true},
		{"localhost no port exact", "http://localhost/callback", "http://localhost/callback", true},
		{"127.0.0.1 dynamic port", "http://127.0.0.1/callback", "http://127.0.0.1:12345/callback", true},
		{"ipv6 loopback dynamic port", "http://[::1]/callback", "http://[::1]:9999/callback", true},

		// Loopback — query string must match
		{"loopback query preserved", "http://localhost/callback?state=abc", "http://localhost:8080/callback?state=abc", true},
		{"loopback extra query rejected", "http://localhost/callback", "http://localhost:8080/callback?evil=1", false},
		{"loopback altered query rejected", "http://localhost/callback?fixed=1", "http://localhost:8080/callback?fixed=1&evil=1", false},
		{"loopback query removed rejected", "http://localhost/callback?fixed=1", "http://localhost:8080/callback", false},
		{"loopback fragment ignored by parser", "http://localhost/callback", "http://localhost:8080/callback#frag", true}, // fragments not sent over HTTP

		// Loopback — must still match scheme and path
		{"different scheme rejected", "http://localhost/callback", "https://localhost:57292/callback", false},
		{"different path rejected", "http://localhost/callback", "http://localhost:57292/other", false},
		{"different host rejected", "http://localhost/callback", "http://127.0.0.1:57292/callback", false},

		// Non-loopback — exact match only (RFC 9700)
		{"non-loopback exact match", "https://app.example.com/callback", "https://app.example.com/callback", true},
		{"non-loopback port differs rejected", "https://app.example.com/callback", "https://app.example.com:8443/callback", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{RedirectURIs: []string{tt.registered}}
			got := c.HasRedirectURI(tt.requested)
			if got != tt.want {
				t.Errorf("HasRedirectURI(%q) = %v, want %v (registered: %q)", tt.requested, got, tt.want, tt.registered)
			}
		})
	}
}

func TestCreateParamsDefaults(t *testing.T) {
	p := CreateParams{Name: "Test"}
	p.Defaults()
	if len(p.GrantTypes) != 1 || p.GrantTypes[0] != "authorization_code" {
		t.Errorf("default grant_types = %v, want [authorization_code]", p.GrantTypes)
	}
	if len(p.ResponseTypes) != 1 || p.ResponseTypes[0] != "code" {
		t.Errorf("default response_types = %v, want [code]", p.ResponseTypes)
	}
	if p.TokenEndpointAuthMethod != "none" {
		t.Errorf("default auth method = %q, want none", p.TokenEndpointAuthMethod)
	}
}

func TestCreateParamsDefaultsNoOverwrite(t *testing.T) {
	p := CreateParams{
		Name:                    "Test",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	p.Defaults()
	if len(p.GrantTypes) != 2 {
		t.Error("Defaults should not overwrite existing grant_types")
	}
	if p.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Error("Defaults should not overwrite existing auth method")
	}
}

// TestStateErrorImplementsDomainError pins Defect B: *StateError
// must satisfy domain.Error so writeDomainOrInternalError maps no-op
// suspend / reactivate transitions to HTTP 409 instead of falling
// through to the 500 default arm.
func TestStateErrorImplementsDomainError(t *testing.T) {
	e := &StateError{From: StatusSuspended, To: StatusSuspended}
	if !domain.IsError(e) {
		t.Fatal("*StateError must satisfy domain.Error")
	}
	if got := domain.ErrorCode(e); got != domain.CodeConflict {
		t.Errorf("Code() = %q, want %q", got, domain.CodeConflict)
	}

	// errors.As must reach the typed error through the wrap chain that
	// AdminService uses (`fmt.Errorf("suspend: %w", err)`).
	wrapped := fmt.Errorf("suspend: %w", e)
	var se *StateError
	if !errors.As(wrapped, &se) {
		t.Fatal("errors.As did not unwrap *StateError through fmt.Errorf %w")
	}
	if got := domain.ErrorCode(wrapped); got != domain.CodeConflict {
		t.Errorf("ErrorCode(wrapped) = %q, want %q", got, domain.CodeConflict)
	}
}
