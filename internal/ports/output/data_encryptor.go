package output

import "context"

// DataEncryptor encrypts and decrypts sensitive values for storage.
// Context is used for observability and cancellation only — no context-derived keys.
// ownerContext is an opaque string that scopes derived keys: prevents cross-owner decrypt.
// For the aes_master driver, ownerContext feeds HKDF info parameter.
// For vault_transit_encrypt, it is sent as the context parameter to the Vault API (base64-encoded).
//
// Convention for ownerContext values:
//   - Upstream connection: "connection:{ownerID}:{service}:{connectionID}"
//   - Signing key encryption: "signing-key:{keyID}"
//
// Retry policy: ErrEncryptionFailed means bad input — do not retry.
// ErrEncryptorUnavailable means transient backend failure — caller may retry.
type DataEncryptor interface {
	Encrypt(ctx context.Context, plaintext []byte, ownerContext string) (ciphertext []byte, err error)
	Decrypt(ctx context.Context, ciphertext []byte, ownerContext string) (plaintext []byte, err error)
	// DriverName returns the configured driver name for audit/logging (never logs keys).
	DriverName() string
}
