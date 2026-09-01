package static

import (
	"context"

	"github.com/authplane/authserver/internal/ports/output"
)

// DataEncryptorFieldEncryptor implements output.FieldEncryptor over an
// output.DataEncryptor, composing the ownerContext from Owner as "{kind}:{id}".
type DataEncryptorFieldEncryptor struct {
	enc output.DataEncryptor
}

// NewDataEncryptorFieldEncryptor wraps a DataEncryptor.
func NewDataEncryptorFieldEncryptor(enc output.DataEncryptor) *DataEncryptorFieldEncryptor {
	return &DataEncryptorFieldEncryptor{enc: enc}
}

var _ output.FieldEncryptor = (*DataEncryptorFieldEncryptor)(nil)

func (f *DataEncryptorFieldEncryptor) Encrypt(ctx context.Context, plaintext []byte, owner output.Owner) ([]byte, error) {
	return f.enc.Encrypt(ctx, plaintext, ownerContext(owner))
}

func (f *DataEncryptorFieldEncryptor) Decrypt(ctx context.Context, ciphertext []byte, owner output.Owner) ([]byte, error) {
	return f.enc.Decrypt(ctx, ciphertext, ownerContext(owner))
}

func (f *DataEncryptorFieldEncryptor) DriverName() string { return f.enc.DriverName() }

// ownerContext composes the encryption owner context. The broker-provider / oidc
// prefixes are deliberately distinct from broker_grants' "broker:" prefix so the
// stores can never cross-decrypt.
func ownerContext(o output.Owner) string { return string(o.Kind) + ":" + o.ID }
