package token

import (
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain/scope"
)

func TestMachineToken_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "not expired",
			expiresAt: time.Now().UTC().Add(1 * time.Hour),
			want:      false,
		},
		{
			name:      "expired",
			expiresAt: time.Now().UTC().Add(-1 * time.Second),
			want:      true,
		},
		{
			name:      "just expired",
			expiresAt: time.Now().UTC().Add(-1 * time.Millisecond),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mt := MachineToken{
				JTI:       "test-jti",
				ClientID:  "client-1",
				Scopes:    scope.New("read", "write"),
				Resource:  "https://api.example.com",
				IssuedAt:  time.Now().UTC(),
				ExpiresAt: tt.expiresAt,
			}
			if got := mt.IsExpired(); got != tt.want {
				t.Errorf("MachineToken.IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMachineToken_Fields(t *testing.T) {
	now := time.Now().UTC()
	scopes := scope.New("tools/query", "tools/write")

	mt := MachineToken{
		JTI:       "jti-abc-123",
		ClientID:  "my-service",
		Scopes:    scopes,
		Resource:  "https://mcp.example.com",
		IssuedAt:  now,
		ExpiresAt: now.Add(1 * time.Hour),
		Revoked:   false,
	}

	if mt.JTI != "jti-abc-123" {
		t.Errorf("JTI = %q, want %q", mt.JTI, "jti-abc-123")
	}
	if mt.ClientID != "my-service" {
		t.Errorf("ClientID = %q, want %q", mt.ClientID, "my-service")
	}
	if !mt.Scopes.Contains("tools/query") {
		t.Error("Scopes should contain tools/query")
	}
	if !mt.Scopes.Contains("tools/write") {
		t.Error("Scopes should contain tools/write")
	}
	if mt.Resource != "https://mcp.example.com" {
		t.Errorf("Resource = %q, want %q", mt.Resource, "https://mcp.example.com")
	}
	if !mt.IssuedAt.Equal(now) {
		t.Errorf("IssuedAt = %v, want %v", mt.IssuedAt, now)
	}
	if !mt.ExpiresAt.Equal(now.Add(1 * time.Hour)) {
		t.Errorf("ExpiresAt = %v, want %v", mt.ExpiresAt, now.Add(1*time.Hour))
	}
	if mt.Revoked {
		t.Error("Revoked should be false initially")
	}
}
