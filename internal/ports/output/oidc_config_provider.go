package output

import "context"

// OIDCConfig is the upstream OIDC configuration used to talk to the IdP.
//
// ClientSecret and ClientSecretRef carry the raw secret source, not a
// pre-resolved plaintext string. They are mutually exclusive — config
// validation rejects setting both — so exactly one is populated: an inline
// client_secret in ClientSecret, or an env-var name in ClientSecretRef.
// Resolution to plaintext happens JIT at the point of use (exchangeCode) via a
// SecretResolver, so Config(ctx) performs no I/O.
type OIDCConfig struct {
	// Enabled reports whether OIDC federation is on for the request. The
	// default static adapter returns the boot value; a substitute adapter may
	// resolve it per request.
	Enabled bool

	Issuer             string
	ClientID           string
	ClientSecret       []byte // at-rest secret bytes (raw plaintext by default; ciphertext with an encrypted store); see type doc
	ClientSecretRef    string // env-var / secret ref name (mutually exclusive with ClientSecret)
	RedirectURI        string
	Scopes             []string
	IncludeGroupsScope bool
	ConnectorID        string

	// JWKS, when non-nil, is the raw JSON Web Key Set used to verify ID tokens.
	// When nil, the key set is fetched from the issuer's discovery document.
	JWKS []byte
}

// OIDCConfigProvider supplies the upstream OIDC configuration for a request.
//
// SSRF note: the returned Issuer is used to fetch the discovery document and
// JWKS over the network. The default static provider returns a fixed,
// operator-configured issuer, and the OIDC adapter dials through an SSRF-safe
// transport. An implementation that derives the Issuer from request-influenced
// data must ensure it cannot be pointed at internal addresses.
type OIDCConfigProvider interface {
	Config(ctx context.Context) (OIDCConfig, error)
}
