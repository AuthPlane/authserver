package resource_test

import (
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain/resource"
)

func TestConnectPendingState_RoundTrip(t *testing.T) {
	exp := time.Now().Add(5 * time.Minute)
	s := resource.ConnectPendingState{
		ID:           "state-1",
		UserID:       "user-1",
		ProviderID:   "bp-1",
		ResourceID:   "res-1",
		CodeVerifier: "verifier-bytes",
		ReturnURL:    "https://app.example.com/callback",
		Scopes:       []string{"read", "write"},
		ExpiresAt:    exp,
	}
	if s.ID != "state-1" || s.ProviderID != "bp-1" || s.ResourceID != "res-1" {
		t.Errorf("FK fields did not round-trip: %+v", s)
	}
	if !s.ExpiresAt.Equal(exp) {
		t.Errorf("ExpiresAt round-trip failed: %v vs %v", s.ExpiresAt, exp)
	}
	if len(s.Scopes) != 2 || s.Scopes[0] != "read" || s.Scopes[1] != "write" {
		t.Errorf("Scopes did not round-trip: %v", s.Scopes)
	}
}

func TestConnectPendingState_IsExpired(t *testing.T) {
	now := time.Now()
	t.Run("future expiry is not expired", func(t *testing.T) {
		s := resource.ConnectPendingState{ExpiresAt: now.Add(time.Minute)}
		if s.IsExpired(now) {
			t.Error("future expiry should not be expired")
		}
	})
	t.Run("past expiry is expired", func(t *testing.T) {
		s := resource.ConnectPendingState{ExpiresAt: now.Add(-time.Minute)}
		if !s.IsExpired(now) {
			t.Error("past expiry should be expired")
		}
	})
	t.Run("equal to now is expired", func(t *testing.T) {
		s := resource.ConnectPendingState{ExpiresAt: now}
		if !s.IsExpired(now) {
			t.Error("now == ExpiresAt should be expired")
		}
	})
	t.Run("zero ExpiresAt is never expired", func(t *testing.T) {
		s := resource.ConnectPendingState{}
		if s.IsExpired(now) {
			t.Error("zero ExpiresAt should be treated as no expiry")
		}
	})
}
