package session

import (
	"testing"
	"time"
)

func TestIsExpired(t *testing.T) {
	s := &AuthSession{ExpiresAt: time.Now().UTC().Add(-1 * time.Minute)}
	if !s.IsExpired() {
		t.Error("session in the past should be expired")
	}

	s2 := &AuthSession{ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}
	if s2.IsExpired() {
		t.Error("session in the future should not be expired")
	}
}

func TestIsConsumed(t *testing.T) {
	s := &AuthSession{}
	if s.IsConsumed() {
		t.Error("new session should not be consumed")
	}
}

func TestConsume(t *testing.T) {
	s := &AuthSession{}
	if err := s.Consume(); err != nil {
		t.Fatalf("first consume should succeed: %v", err)
	}
	if !s.IsConsumed() {
		t.Error("session should be consumed after Consume()")
	}
	if s.ConsumedAt == nil {
		t.Error("ConsumedAt should be set")
	}
}

func TestConsumeIdempotencyRejected(t *testing.T) {
	s := &AuthSession{}
	_ = s.Consume()
	if err := s.Consume(); err == nil {
		t.Error("double consume should fail")
	}
	if err := s.Consume(); err != ErrAlreadyConsumed {
		t.Errorf("error should be ErrAlreadyConsumed, got %v", err)
	}
}

func TestAuthCodeTTL(t *testing.T) {
	if AuthCodeTTL != 10*time.Minute {
		t.Errorf("AuthCodeTTL = %v, want 10m", AuthCodeTTL)
	}
}
