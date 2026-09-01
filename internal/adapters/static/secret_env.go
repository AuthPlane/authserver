package static

import (
	"context"
	"fmt"
	"os"

	"github.com/authplane/authserver/internal/brokerproto"
)

// EnvSecrets is the low-level env helper used by ConfigSecretBackend: it treats
// the opaque secret reference as an environment-variable name and looks it up
// behind the brokerproto.ValidEnvVarName allowlist (CONNECTOR_* /
// AUTHPLANE_VAULT_*). It is the env arm of the composite ConfigSecretBackend,
// not a port implementation in its own right.
type EnvSecrets struct {
	// legacy names a set of refs exempt from the allowlist because they came
	// from a pre-v0.1.2 config key (oidc.client_secret_env), whose documented
	// examples used unprefixed names like OIDC_CLIENT_SECRET. The exemption is
	// narrow by construction: only refs the operator's own config file already
	// carried are admitted, never one from a database row.
	legacy map[string]struct{}
}

// NewEnvSecrets builds the env-backed secret helper. Any legacyRefs given are
// admitted despite failing the allowlist — see EnvSecrets.legacy.
func NewEnvSecrets(legacyRefs ...string) EnvSecrets {
	if len(legacyRefs) == 0 {
		return EnvSecrets{}
	}
	legacy := make(map[string]struct{}, len(legacyRefs))
	for _, ref := range legacyRefs {
		if ref != "" {
			legacy[ref] = struct{}{}
		}
	}
	return EnvSecrets{legacy: legacy}
}

// Resolve validates ref against the env-var allowlist, then looks it up in the
// process environment. ctx is unused: env lookup is process-global.
func (e EnvSecrets) Resolve(_ context.Context, ref string) (string, error) {
	if !brokerproto.ValidEnvVarName(ref) && !e.isLegacy(ref) {
		return "", fmt.Errorf("secret reference %q is not an allowed env var name", ref)
	}
	return os.Getenv(ref), nil
}

func (e EnvSecrets) isLegacy(ref string) bool {
	_, ok := e.legacy[ref]
	return ok
}
