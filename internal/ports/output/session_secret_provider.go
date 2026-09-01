package output

import "context"

// SessionSecretProvider supplies the HMAC secret used to sign and verify
// session cookies and the derived CSRF tokens for a request.
//
// The default provider (static.NewSessionSecretProvider) returns a single,
// boot-captured secret for every call (per-deployment behavior). Substituting it
// lets the secret be sourced per request — e.g. from a KMS/HSM, an env-keyed
// rotation scheme, or any backend that resolves the signing key from the request
// context.
//
// Contract:
//   - Implementations MUST honor ctx cancellation.
//   - A non-nil error MUST be treated as fatal for the current request: callers
//     MUST NOT fall back to any other secret. Silent fallback would let an
//     attacker who can induce a resolution error bypass the signed cookie — a
//     forgery vector.
//   - Callers MUST NOT mutate the returned slice; implementations MAY return
//     shared backing storage without copying.
type SessionSecretProvider interface {
	Secret(ctx context.Context) ([]byte, error)
}
