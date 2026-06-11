package token

import (
	"testing"
	"time"
)

func TestFamilyIsActive(t *testing.T) {
	f := &Family{Status: FamilyActive}
	if !f.IsActive() {
		t.Error("new family should be active")
	}
}

func TestFamilyRevoke(t *testing.T) {
	f := &Family{Status: FamilyActive}
	f.Revoke()
	if f.IsActive() {
		t.Error("revoked family should not be active")
	}
	if f.Status != FamilyRevoked {
		t.Errorf("status = %q, want revoked", f.Status)
	}
	if f.RevokedAt == nil {
		t.Error("RevokedAt should be set")
	}
}

func TestFamilyDoubleRevoke(t *testing.T) {
	f := &Family{Status: FamilyActive}
	f.Revoke()
	first := *f.RevokedAt
	f.Revoke() // should not panic
	if f.Status != FamilyRevoked {
		t.Error("should still be revoked")
	}
	// RevokedAt may be updated, that's fine
	_ = first
}

func TestRefreshTokenIsExpired(t *testing.T) {
	expired := &RefreshToken{ExpiresAt: time.Now().UTC().Add(-1 * time.Hour)}
	if !expired.IsExpired() {
		t.Error("token in the past should be expired")
	}

	valid := &RefreshToken{ExpiresAt: time.Now().UTC().Add(1 * time.Hour)}
	if valid.IsExpired() {
		t.Error("token in the future should not be expired")
	}
}

func TestRefreshTokenConsume(t *testing.T) {
	rt := &RefreshToken{}
	if rt.IsConsumed() {
		t.Error("new token should not be consumed")
	}
	if err := rt.Consume(); err != nil {
		t.Fatalf("first consume should succeed: %v", err)
	}
	if !rt.IsConsumed() {
		t.Error("token should be consumed after Consume()")
	}
	if rt.ConsumedAt == nil {
		t.Error("ConsumedAt should be set")
	}
}

func TestRefreshTokenDoubleConsumeDetectsTheft(t *testing.T) {
	rt := &RefreshToken{}
	_ = rt.Consume()
	err := rt.Consume()
	if err == nil {
		t.Fatal("double consume should fail (theft detection)")
	}
	if err != ErrAlreadyConsumed {
		t.Errorf("error should be ErrAlreadyConsumed, got %v", err)
	}
}

func TestTokenFamilyLifecycle(t *testing.T) {
	// Simulate: create family → issue RT1 → consume RT1 (rotate) → issue RT2 → reuse RT1 → revoke family
	family := &Family{
		ID:        "fam-1",
		ClientID:  "client-1",
		UserID:    "user-1",
		Scope:     "tools/read",
		Resource:  "https://mcp.example.com",
		Status:    FamilyActive,
		CreatedAt: time.Now().UTC(),
	}

	rt1 := &RefreshToken{
		ID:        "rt-1",
		FamilyID:  family.ID,
		TokenHash: "hash-of-rt1",
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
		CreatedAt: time.Now().UTC(),
	}

	// Consume RT1 (normal rotation)
	if err := rt1.Consume(); err != nil {
		t.Fatalf("consume RT1: %v", err)
	}

	// Attempt reuse of RT1 → detect theft
	err := rt1.Consume()
	if err != ErrAlreadyConsumed {
		t.Fatalf("reuse should return ErrAlreadyConsumed, got %v", err)
	}

	// Revoke entire family
	family.Revoke()
	if family.IsActive() {
		t.Error("family should be revoked after theft detection")
	}
}
