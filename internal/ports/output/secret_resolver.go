package output

import (
	"context"
	"errors"

	"github.com/authplane/authserver/internal/domain/resource"
)

// ErrSecretUnresolvable indicates a SecretSource carries at-rest Data but the
// wired resolver cannot turn it into plaintext (e.g. encrypted bytes reached a
// process with no decryptor). It is a SERVER misconfiguration, not client input —
// the strict backend returns it instead of surfacing raw bytes. Wrap it.
var ErrSecretUnresolvable = errors.New("secret cannot be resolved")

// SecretSource locates one config secret for resolution. Resolution order:
// Data (decrypted under the Owner-derived ownerContext) → Ref (env var).
type SecretSource struct {
	Data  []byte // at-rest bytes (ciphertext, or inline plaintext on the OIDC OSS path)
	Ref   string // env-var name — fallback
	Owner Owner  // owning entity; forms the decrypt ownerContext
}

// SecretResolver resolves a SecretSource to its plaintext at use time. It does
// not branch on the recorded backend name — it decrypts with the wired encryptor
// (mirroring broker_grants). Wired in cmd/.
type SecretResolver interface {
	Resolve(ctx context.Context, src SecretSource) (string, error)
}

// GetSecretSourceForOIDC builds the SecretSource for an OIDCConfig's client
// secret, binding the decrypt ownerContext to the connector identity.
func GetSecretSourceForOIDC(cfg OIDCConfig) SecretSource {
	return SecretSource{
		Data:  cfg.ClientSecret,
		Ref:   cfg.ClientSecretRef,
		Owner: Owner{Kind: OwnerKindOIDC, ID: oidcOwnerID(cfg.ConnectorID)},
	}
}

// oidcOwnerID is the ownerContext identity for an OIDC connector. connector_id
// is optional in single-connector OSS; falling back to a stable sentinel keeps
// the ownerContext from degenerating to the bare "oidc:" prefix, so per-connector
// isolation stays meaningful if more connectors are ever added. Encrypt and
// decrypt both route through here, so the mapping stays symmetric.
func oidcOwnerID(connectorID string) string {
	if connectorID == "" {
		return "default"
	}
	return connectorID
}

// GetSecretSourceForBrokerProvider builds the SecretSource for a BrokerProvider's
// secret field, binding the decrypt ownerContext to the provider identity.
func GetSecretSourceForBrokerProvider(p *resource.BrokerProvider, ref string) SecretSource {
	return SecretSource{
		Data:  p.EncSecretData,
		Ref:   ref,
		Owner: Owner{Kind: OwnerKindBrokerProvider, ID: p.ID},
	}
}
