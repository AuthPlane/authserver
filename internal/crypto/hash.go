package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// HashSHA256 returns the hex-encoded SHA-256 hash of s.
// Used for hashing auth codes and refresh tokens before storage.
func HashSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// CompareHash performs a constant-time comparison of a hex-encoded SHA-256
// hash against the hash of plain. Returns true if they match.
func CompareHash(hash, plain string) bool {
	computed := HashSHA256(plain)
	return subtle.ConstantTimeCompare([]byte(hash), []byte(computed)) == 1
}
