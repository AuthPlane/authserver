package static

import (
	"context"
	"fmt"

	"github.com/authplane/authserver/internal/ports/output"
)

// ConfigSecretBackend implements both output.SecretEncoder and
// output.SecretResolver over an env helper + an optional FieldEncryptor. With no
// FieldEncryptor (no DataEncryptor configured) it runs env-only: Encode rejects a
// raw Value and Resolve never decrypts.
//
// allowInline selects the at-rest policy when NO encryptor is wired, and is a
// property of the constructed backend — not of the caller's input — so it cannot
// be flipped per call:
//   - allowInline=false (NewConfigSecretBackend): a raw Value is rejected by
//     Encode and a populated Data is rejected by Resolve (fail closed). This is
//     the broker policy: broker secrets are only ever stored encrypted.
//   - allowInline=true (NewConfigSecretBackendInline): a raw Value is carried
//     as-is plaintext and read back as-is. This is the OIDC OSS policy, where an
//     inline client_secret in config is a valid plaintext value.
//
// With an encryptor wired both backends behave identically (encrypt on Encode,
// decrypt on Resolve); allowInline only governs the no-encryptor path.
type ConfigSecretBackend struct {
	env         EnvSecrets
	fieldEnc    output.FieldEncryptor // nil ⇒ env-only
	allowInline bool                  // permit plaintext at-rest when no encryptor (OIDC only)
}

// NewConfigSecretBackend builds the strict (encrypt-or-ref) config-secret
// backend. A raw Value with no encryptor is rejected on both Encode and Resolve.
// Wire this for broker secrets, which are never stored as plaintext.
func NewConfigSecretBackend(fieldEnc output.FieldEncryptor) *ConfigSecretBackend {
	return &ConfigSecretBackend{env: NewEnvSecrets(), fieldEnc: fieldEnc}
}

// NewConfigSecretBackendInline builds the inline-tolerant backend: with no
// encryptor a raw Value is carried as plaintext at rest and read back as-is.
// Wire this for the OIDC client secret, where an inline config value is valid.
// legacyRefs are pre-v0.1.2 secret references (from oidc.client_secret_env)
// admitted despite the env-var allowlist; see EnvSecrets.
func NewConfigSecretBackendInline(legacyRefs ...string) *ConfigSecretBackend {
	return &ConfigSecretBackend{env: NewEnvSecrets(legacyRefs...), fieldEnc: nil, allowInline: true}
}

var (
	_ output.SecretEncoder  = (*ConfigSecretBackend)(nil)
	_ output.SecretResolver = (*ConfigSecretBackend)(nil)
)

// Encode converts operator input to its at-rest form. A raw Value is encrypted
// under the Owner-derived ownerContext when an encryptor is configured. With NO
// encryptor the value is carried as-is plaintext only when this backend allows
// inline (the OIDC policy); otherwise it is rejected (the broker policy). An
// empty Value passes the Ref through unchanged.
func (b *ConfigSecretBackend) Encode(ctx context.Context, in output.SecretInput) (output.EncodedSecret, error) {
	if in.Value != "" {
		if b.fieldEnc == nil {
			if b.allowInline {
				// No encryptor ⇒ the value is already plaintext; carry it as-is.
				return output.EncodedSecret{Data: []byte(in.Value)}, nil
			}
			return output.EncodedSecret{}, fmt.Errorf(
				"%w: the env backend stores no inline values; set an env var and pass its name in %s_ref",
				output.ErrSecretInputRejected, in.Field)
		}
		ct, err := b.fieldEnc.Encrypt(ctx, []byte(in.Value), in.Owner)
		if err != nil {
			return output.EncodedSecret{}, fmt.Errorf("encrypt secret for field %q: %w", in.Field, err)
		}
		return output.EncodedSecret{Data: ct, Backend: b.fieldEnc.DriverName()}, nil
	}
	return output.EncodedSecret{Ref: in.Ref}, nil
}

// Resolve returns the plaintext for a SecretSource. Resolution order is
// Data (decrypted under the Owner-derived ownerContext) → Ref (env var).
//
// When an encryptor is NOT configured and Data is populated, the bytes are
// treated as plaintext and returned as-is ONLY when this backend allows inline
// (the OIDC OSS path); the strict (broker) backend fails closed instead, so an
// encrypted column read by a process with no decryptor can never silently
// surface its ciphertext as the secret. With an encryptor wired, Data is always
// decrypted.
func (b *ConfigSecretBackend) Resolve(ctx context.Context, src output.SecretSource) (string, error) {
	if len(src.Data) > 0 {
		if b.fieldEnc == nil {
			if b.allowInline {
				// No encryptor ⇒ Data is already-plaintext (OIDC OSS-inline path).
				return string(src.Data), nil
			}
			return "", fmt.Errorf(
				"%w: secret has at-rest data but no decryptor is configured",
				output.ErrSecretUnresolvable)
		}
		pt, err := b.fieldEnc.Decrypt(ctx, src.Data, src.Owner)
		if err != nil {
			return "", fmt.Errorf("decrypt config secret: %w", err)
		}
		return string(pt), nil
	}
	return b.env.Resolve(ctx, src.Ref)
}
