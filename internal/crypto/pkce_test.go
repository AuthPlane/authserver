package crypto

import (
	"strings"
	"testing"
)

func TestPKCERoundTrip(t *testing.T) {
	verifier := GenerateVerifier()
	challenge := ComputeS256Challenge(verifier)

	if err := VerifyS256(verifier, challenge); err != nil {
		t.Errorf("valid S256 round-trip should succeed: %v", err)
	}
}

func TestPKCEWrongVerifier(t *testing.T) {
	verifier := GenerateVerifier()
	challenge := ComputeS256Challenge(verifier)

	wrongVerifier := GenerateVerifier()
	if err := VerifyS256(wrongVerifier, challenge); err == nil {
		t.Error("wrong verifier should fail")
	}
}

func TestPKCEEmptyVerifier(t *testing.T) {
	challenge := ComputeS256Challenge("some-verifier-value-that-is-long-enough-ok")
	if err := VerifyS256("", challenge); err == nil {
		t.Error("empty verifier should fail")
	}
}

func TestPKCEEmptyChallenge(t *testing.T) {
	verifier := GenerateVerifier()
	if err := VerifyS256(verifier, ""); err == nil {
		t.Error("empty challenge should fail")
	}
}

func TestPKCEShortVerifier(t *testing.T) {
	short := "tooshort"
	challenge := ComputeS256Challenge(short)
	if err := VerifyS256(short, challenge); err == nil {
		t.Error("short verifier should fail")
	}
}

func TestPKCETooLongVerifier(t *testing.T) {
	long := strings.Repeat("a", PKCEMaxVerifierLength+1)
	challenge := ComputeS256Challenge(long)
	if err := VerifyS256(long, challenge); err == nil {
		t.Error("verifier exceeding max length should fail")
	}
}

func TestPKCEExactMinLength(t *testing.T) {
	verifier := strings.Repeat("a", PKCEMinVerifierLength)
	challenge := ComputeS256Challenge(verifier)
	if err := VerifyS256(verifier, challenge); err != nil {
		t.Errorf("verifier at exact min length should succeed: %v", err)
	}
}

func TestPKCEExactMaxLength(t *testing.T) {
	verifier := strings.Repeat("z", PKCEMaxVerifierLength)
	challenge := ComputeS256Challenge(verifier)
	if err := VerifyS256(verifier, challenge); err != nil {
		t.Errorf("verifier at exact max length should succeed: %v", err)
	}
}

func TestValidateChallengeMethodS256(t *testing.T) {
	if err := ValidateChallengeMethod("S256"); err != nil {
		t.Errorf("S256 should be accepted: %v", err)
	}
}

func TestValidateChallengeMethodPlainRejected(t *testing.T) {
	if err := ValidateChallengeMethod("plain"); err == nil {
		t.Error("plain should be rejected")
	}
}

func TestValidateChallengeMethodEmptyRejected(t *testing.T) {
	if err := ValidateChallengeMethod(""); err == nil {
		t.Error("empty method should be rejected")
	}
}

func TestValidateChallengeMethodUnknownRejected(t *testing.T) {
	if err := ValidateChallengeMethod("S512"); err == nil {
		t.Error("unknown method should be rejected")
	}
}

// Matrix: 1.2.9 — code_verifier with invalid characters must be rejected
func TestPKCEInvalidCharacters(t *testing.T) {
	tests := []struct {
		name     string
		verifier string
	}{
		{"space", "abcdefghijklmnopqrstuvwxyz01234567890 abcdefg"},
		{"plus", "abcdefghijklmnopqrstuvwxyz01234567890+abcdefg"},
		{"slash", "abcdefghijklmnopqrstuvwxyz01234567890/abcdefg"},
		{"equals", "abcdefghijklmnopqrstuvwxyz01234567890=abcdefg"},
		{"hash", "abcdefghijklmnopqrstuvwxyz01234567890#abcdefg"},
		{"at_sign", "abcdefghijklmnopqrstuvwxyz01234567890@abcdefg"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenge := ComputeS256Challenge(tt.verifier)
			if err := VerifyS256(tt.verifier, challenge); err == nil {
				t.Errorf("verifier with %s should be rejected", tt.name)
			}
		})
	}
}

// Matrix: 1.2.9 — valid PKCE characters must be accepted
func TestPKCEValidCharacters(t *testing.T) {
	// RFC 7636 §4.1: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
	verifier := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr-._~"
	challenge := ComputeS256Challenge(verifier)
	if err := VerifyS256(verifier, challenge); err != nil {
		t.Errorf("verifier with all valid characters should succeed: %v", err)
	}
}

func TestGenerateVerifierLength(t *testing.T) {
	v := GenerateVerifier()
	if len(v) < PKCEMinVerifierLength {
		t.Errorf("generated verifier length %d < min %d", len(v), PKCEMinVerifierLength)
	}
	if len(v) > PKCEMaxVerifierLength {
		t.Errorf("generated verifier length %d > max %d", len(v), PKCEMaxVerifierLength)
	}
}
