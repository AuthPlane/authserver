package static

import (
	"context"

	"github.com/authplane/authserver/internal/ports/output"
)

// OIDCConfigProvider returns the upstream OIDC configuration carrying the raw
// secret source. Resolution to plaintext is deferred to the point of use
// (exchangeCode in the oidc.Provider) via a SecretResolver, so Config(ctx)
// performs no I/O and holds no resolver dependency.
//
// The caller (cmd/serve.go) passes the secret source straight through in its
// config form: the inline client_secret as raw plaintext bytes (OSS — no
// encryptor), or the client_secret_ref env-var name. The two are mutually
// exclusive — config validation rejects setting both — so the DTO carries
// exactly one of {ClientSecret, ClientSecretRef} and the downstream resolver
// sees either Data or Ref, never both. This provider enforces no precedence; it
// only transports the config.
type OIDCConfigProvider struct {
	base output.OIDCConfig // all fields except the secret
}

// NewOIDCConfigProvider builds the provider from boot configuration. The OIDC
// config carries exactly one secret source (inline client_secret bytes or a
// client_secret_ref name; config validation rejects both). No resolver is
// injected here; resolution happens JIT at exchangeCode.
func NewOIDCConfigProvider(c output.OIDCConfig) *OIDCConfigProvider {
	return &OIDCConfigProvider{base: c}
}

// Config returns the OIDC configuration with the at-rest secret source
// populated. Exactly one of ClientSecret / ClientSecretRef is set. No I/O is
// performed.
func (p *OIDCConfigProvider) Config(_ context.Context) (output.OIDCConfig, error) {
	return p.base, nil
}

var _ output.OIDCConfigProvider = (*OIDCConfigProvider)(nil)
