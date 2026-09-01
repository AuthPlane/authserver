package output

import (
	"context"
	"errors"

	"github.com/authplane/authserver/internal/domain/resource"
)

// ErrSecretInputRejected indicates the SecretInput is not acceptable to the wired
// backend (e.g. a raw Value but no encryptor configured). It signals a CLIENT
// mistake (admin layer maps it to 400). Wrap it: fmt.Errorf("%w: …", Err…).
var ErrSecretInputRejected = errors.New("secret input not acceptable")

// SecretInput carries what the operator provided for one secret field plus the
// owning entity identity. Value and Ref are mutually exclusive.
type SecretInput struct {
	Value string // raw secret to encrypt (exclusive with Ref)
	Ref   string // env-var name to record (passthrough)
	Owner Owner  // owning entity → ownerContext for encryption (AAD binding)
	Field string // for diagnostics / the env-path rejection message
}

// EncodedSecret is the at-rest form of a secret — mirrors SecretSource plus the
// backend that produced the ciphertext (parity with broker_grants.enc_backend).
type EncodedSecret struct {
	Data    []byte // at-rest bytes for the column: ciphertext, or inline plaintext (OIDC OSS)
	Backend string // DriverName() of the encryptor (empty on the ref / inline paths)
	Ref     string // populated when the secret is an env reference
}

// SecretEncoder converts operator input into the at-rest representation. It does
// NOT persist — the store persists Data+Backend (column) or Ref
// (config_data). Wired in cmd/.
type SecretEncoder interface {
	Encode(ctx context.Context, in SecretInput) (EncodedSecret, error)
}

// GetSecretInputForBrokerProvider builds the SecretInput for one BrokerProvider
// secret field, binding the encryption ownerContext to the provider's identity.
func GetSecretInputForBrokerProvider(p *resource.BrokerProvider, value, ref, field string) SecretInput {
	return SecretInput{
		Value: value,
		Ref:   ref,
		Owner: Owner{Kind: OwnerKindBrokerProvider, ID: p.ID},
		Field: field,
	}
}
