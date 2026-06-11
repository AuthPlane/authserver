package output

import (
	"context"
	"crypto"
)

// SigningKey holds a signing key and its metadata at the port level.
// This uses Go stdlib crypto types only — no dependency on internal/crypto
// or external libraries.
//
// Adapters (keyfile, and future KMS backends like Vault, GCP/AWS/Azure KMS)
// convert between this port type and their native representation.
// For KMS backends that don't expose raw private keys, the PrivateKey field
// holds a crypto.Signer that delegates signing to the remote KMS.
type SigningKey struct {
	PrivateKey crypto.Signer
	PublicKey  crypto.PublicKey
	Algorithm  string // "ES256" or "RS256"
	KeyID      string
}

// KeyStore manages signing key persistence.
// Implementations range from local PEM files (keyfile adapter) to
// remote KMS systems. The interface is intentionally minimal to support
// both local and remote key management.
type KeyStore interface {
	// LoadCurrent returns the current signing key pair.
	// Returns nil, nil if no key exists (first run).
	LoadCurrent(ctx context.Context) (*SigningKey, error)

	// LoadPrevious returns the previous signing key (for JWKS during rotation).
	// Returns nil, nil if no previous key exists.
	LoadPrevious(ctx context.Context) (*SigningKey, error)

	// Save persists a key pair, rotating the current key to previous.
	Save(ctx context.Context, key *SigningKey) error

	// ListActive returns all active signing keys (current + previous if exists).
	// Used by JWKS service to build the key set in a single call.
	// Returns empty slice (not nil) if no keys exist.
	ListActive(ctx context.Context) ([]*SigningKey, error)
}
