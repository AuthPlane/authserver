package crypto

import (
	"testing"
)

func TestGenerateRandomString(t *testing.T) {
	s1 := GenerateRandomString(32)
	s2 := GenerateRandomString(32)

	if s1 == s2 {
		t.Error("two random strings should not be equal")
	}

	// 32 bytes → 43 base64url chars (no padding)
	if len(s1) != 43 {
		t.Errorf("expected length 43 for 32 bytes, got %d", len(s1))
	}

	// Check URL-safe: no +, /, or =
	for _, c := range s1 {
		if c == '+' || c == '/' || c == '=' {
			t.Errorf("character %c is not URL-safe", c)
		}
	}
}

func TestGenerateRandomStringLengths(t *testing.T) {
	tests := []struct {
		bytes     int
		wantChars int
	}{
		{16, 22}, // client ID length
		{32, 43}, // client secret / auth code length
		{64, 86}, // extra long
	}
	for _, tt := range tests {
		s := GenerateRandomString(tt.bytes)
		if len(s) != tt.wantChars {
			t.Errorf("GenerateRandomString(%d): len = %d, want %d", tt.bytes, len(s), tt.wantChars)
		}
	}
}

func TestGenerateClientID(t *testing.T) {
	id := GenerateClientID()
	if len(id) != 22 {
		t.Errorf("client ID length = %d, want 22", len(id))
	}
}

func TestGenerateClientSecret(t *testing.T) {
	secret := GenerateClientSecret()
	if len(secret) != 43 {
		t.Errorf("client secret length = %d, want 43", len(secret))
	}
}

func TestGenerateAuthCode(t *testing.T) {
	code := GenerateAuthCode()
	if len(code) != 43 {
		t.Errorf("auth code length = %d, want 43", len(code))
	}
}
