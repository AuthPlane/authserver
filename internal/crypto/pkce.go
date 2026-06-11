package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"regexp"
)

const (
	// PKCEMinVerifierLength is the minimum code_verifier length per RFC 7636 §4.1.
	PKCEMinVerifierLength = 43
	// PKCEMaxVerifierLength is the maximum code_verifier length per RFC 7636 §4.1.
	PKCEMaxVerifierLength = 128
)

// GenerateVerifier returns a cryptographically random PKCE code_verifier
// (43 chars from 32 bytes of entropy, URL-safe base64).
func GenerateVerifier() string {
	return GenerateRandomString(32)
}

// ComputeS256Challenge computes the S256 code_challenge for the given verifier.
// challenge = BASE64URL(SHA256(verifier)) per RFC 7636 §4.2.
func ComputeS256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// pkceVerifierRE matches the valid character set per RFC 7636 §4.1:
// [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
var pkceVerifierRE = regexp.MustCompile(`^[A-Za-z0-9\-._~]+$`)

// VerifyS256 verifies a PKCE code_verifier against a stored code_challenge.
// Returns nil on success.
func VerifyS256(verifier, challenge string) error {
	if verifier == "" {
		return fmt.Errorf("code_verifier is required")
	}
	if len(verifier) < PKCEMinVerifierLength || len(verifier) > PKCEMaxVerifierLength {
		return fmt.Errorf("code_verifier length must be between %d and %d", PKCEMinVerifierLength, PKCEMaxVerifierLength)
	}
	if !pkceVerifierRE.MatchString(verifier) {
		return fmt.Errorf("code_verifier contains invalid characters")
	}
	if challenge == "" {
		return fmt.Errorf("code_challenge is required")
	}
	computed := ComputeS256Challenge(verifier)
	if subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) != 1 {
		return fmt.Errorf("code_verifier does not match code_challenge")
	}
	return nil
}

// ValidateChallengeMethod rejects anything other than S256.
// plain is never accepted per security invariant.
func ValidateChallengeMethod(method string) error {
	if method != "S256" {
		return fmt.Errorf("unsupported code_challenge_method %q: only S256 is allowed", method)
	}
	return nil
}
