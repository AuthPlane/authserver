package input

import "context"

// ProtectedResourceMetadata is the application-level, fully-resolved OAuth 2.0
// Protected Resource Metadata document for one registered Resource (RFC 9728
// §2). Like ASMetadata it is NOT the wire DTO — field tags and omitempty rules
// stay in the HTTP adapter as a transport concern.
type ProtectedResourceMetadata struct {
	// Resource is the resource identifier (RFC 9728 §2, REQUIRED). Emitted
	// exactly as registered: a client compares it against the identifier it
	// asked about, so normalizing here would break that comparison.
	Resource string

	// AuthorizationServers lists issuer identifiers a client may obtain tokens
	// from for this Resource. This is the field the whole document exists to
	// carry — it is how a client holding only a resource URL discovers which AS
	// to talk to, without out-of-band configuration.
	AuthorizationServers []string

	// ScopesSupported are the scope names registered for this Resource.
	// RFC 9728 §2 makes it OPTIONAL; the MCP authorization spec leans on it as
	// the fallback when a 401 carries no scope parameter.
	ScopesSupported []string

	// BearerMethodsSupported reports how a token may be presented. Always
	// ["header"]: the MCP spec requires the Authorization header and forbids
	// query-string tokens outright.
	BearerMethodsSupported []string

	// ResourceName is a human-readable display name, shown by clients when
	// asking a user to approve access.
	ResourceName string
}

// PRMetadataPort assembles the Protected Resource Metadata document served by
// GET /.well-known/oauth-protected-resource and its path-suffixed form.
//
// ref identifies which registered Resource is being asked about. Empty means
// the bare well-known path, which addresses a Resource whose identifier is the
// authorization server's own origin. See the service for how a non-empty ref is
// resolved.
type PRMetadataPort interface {
	Metadata(ctx context.Context, ref string) (*ProtectedResourceMetadata, error)
}
