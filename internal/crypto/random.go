// Package crypto provides cryptographic primitives for authserver.
package crypto

import (
	"crypto/rand"
	"encoding/base64"
)

// GenerateRandomString returns a URL-safe base64-encoded random string
// of n random bytes (the encoded string will be longer than n).
func GenerateRandomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// GenerateClientID returns a random client identifier (22 chars, 16 bytes entropy).
func GenerateClientID() string {
	return GenerateRandomString(16)
}

// GenerateClientSecret returns a random client secret (43 chars, 32 bytes entropy).
func GenerateClientSecret() string {
	return GenerateRandomString(32)
}

// GenerateAuthCode returns a random authorization code (43 chars, 32 bytes entropy).
func GenerateAuthCode() string {
	return GenerateRandomString(32)
}
