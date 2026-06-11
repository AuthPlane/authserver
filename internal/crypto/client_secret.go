package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"sync/atomic"
)

// Client-secret hashing.
//
// Client secrets are server-generated, high-entropy random tokens
// (crypto.GenerateClientSecret = 256 bits). bcrypt's work factor exists to slow
// brute force of LOW-entropy human passwords after a hash-DB leak; against a
// 256-bit random secret it adds no meaningful resistance while costing ~hundreds
// of ms per verification. So client secrets use a keyed hash —
// HMAC-SHA256(pepper, secret) — which is as safe here and ~3 orders of magnitude
// cheaper. User passwords keep bcrypt (see HashBcrypt/CompareBcrypt).
//
// This is opt-in: with no pepper configured, client secrets fall back to bcrypt
// (today's behavior). Hashes are scheme-tagged so a deployment can switch on
// the pepper and keep verifying its existing bcrypt-hashed secrets.

// clientSecretScheme prefixes HMAC-hashed client secrets, distinguishing them
// from legacy bcrypt hashes (which start with "$2").
const clientSecretScheme = "hs256$"

// clientSecretPepper is the HMAC key, configured once at startup via
// SetClientSecretPepper. A nil pointer means "no pepper" → bcrypt fallback.
// atomic so the hot verification path reads it without locking.
var clientSecretPepper atomic.Pointer[[]byte]

// ErrClientSecretMismatch is returned when a client secret does not match its
// stored HMAC hash.
var ErrClientSecretMismatch = errors.New("client secret mismatch")

// SetClientSecretPepper configures the HMAC key used to hash and verify client
// secrets. With a non-empty pepper, HashClientSecret produces HMAC-SHA256
// hashes; with an empty pepper it falls back to bcrypt. Existing hashes of
// either scheme continue to verify regardless. Call once at startup, before
// serving requests.
func SetClientSecretPepper(pepper string) {
	if pepper == "" {
		clientSecretPepper.Store(nil)
		return
	}
	b := []byte(pepper)
	clientSecretPepper.Store(&b)
}

func clientPepper() []byte {
	if p := clientSecretPepper.Load(); p != nil {
		return *p
	}
	return nil
}

// HashClientSecret hashes a client secret for storage. With a pepper configured
// it uses HMAC-SHA256 (fast); otherwise it falls back to bcrypt.
func HashClientSecret(plaintext string) (string, error) {
	pepper := clientPepper()
	if len(pepper) == 0 {
		return HashBcrypt(plaintext)
	}
	return clientSecretScheme + hmacSecret(pepper, plaintext), nil
}

// CompareClientSecret verifies a client secret against its stored hash,
// auto-detecting the scheme (HMAC-SHA256 vs legacy bcrypt). Returns nil on a
// match. The comparison is constant-time.
func CompareClientSecret(hash, plaintext string) error {
	if strings.HasPrefix(hash, clientSecretScheme) {
		pepper := clientPepper()
		if len(pepper) == 0 {
			return errors.New("client secret is HMAC-hashed but no pepper is configured")
		}
		want := strings.TrimPrefix(hash, clientSecretScheme)
		got := hmacSecret(pepper, plaintext)
		// Equal-length base64 of 32-byte digests → constant-time compare.
		if hmac.Equal([]byte(want), []byte(got)) {
			return nil
		}
		return ErrClientSecretMismatch
	}
	// Legacy / pepper-less: bcrypt.
	return CompareBcrypt(hash, plaintext)
}

func hmacSecret(pepper []byte, plaintext string) string {
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(plaintext))
	return base64.RawStdEncoding.EncodeToString(mac.Sum(nil))
}
