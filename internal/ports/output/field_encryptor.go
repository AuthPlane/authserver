package output

import "context"

// FieldEncryptor encrypts and decrypts a config secret under an Owner-derived
// ownerContext. It is a thin helper over DataEncryptor that owns the
// Owner→ownerContext convention ("{kind}:{id}"), so that convention lives in one
// place and is reusable by broker, OIDC, and future config stores. DriverName
// names the backend that produced a ciphertext (recorded alongside it for audit
// and crypto-agility).
type FieldEncryptor interface {
	Encrypt(ctx context.Context, plaintext []byte, owner Owner) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte, owner Owner) ([]byte, error)
	DriverName() string
}
