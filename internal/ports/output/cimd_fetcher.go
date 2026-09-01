package output

import (
	"context"
	"time"
)

// CIMDFetcher fetches and validates Client ID Metadata Documents.
type CIMDFetcher interface {
	// Fetch retrieves a CIMD from the given URL. The document is validated:
	// client_id must match the URL, required fields (redirect_uris, client_name)
	// must be present. The per-request cfg supplies the RequireHTTPS/CacheTTL/
	// FetchTimeout knobs — the fetcher holds no policy of its own; the caller
	// (the service, resolving the per-request CIMDConfigProvider) is the single
	// source of truth.
	Fetch(ctx context.Context, url string, cfg CIMDFetchConfig) (*CIMDDocument, error)
}

// CIMDFetchConfig holds the per-request knobs the fetcher honors. Enabled is not
// a fetch concern and is intentionally absent (the service gates on it before
// fetching).
type CIMDFetchConfig struct {
	// RequireHTTPS rejects non-HTTPS document URLs. It ALSO selects the HTTP
	// transport: true uses an SSRF-safe transport that blocks dial-time
	// connections to private/reserved IPs (incl. DNS names resolving to them);
	// false uses the plain transport (loopback allowed, for dev/test). Setting
	// it false for a non-loopback reason silently drops dial-time SSRF blocking,
	// so a substitute provider should keep it true outside loopback testing.
	RequireHTTPS bool
	// CacheTTL bounds how long a fetched document is reused. The fetcher cache is
	// process-global and keyed by URL only, so this is best-effort across
	// differing per-request values: the request that POPULATES an entry stamps
	// its lifetime, and a later request for the same URL gets that entry until it
	// expires regardless of its own CacheTTL (a shorter TTL is not honored until
	// the populating entry expires). Uniform under the OSS static default.
	CacheTTL     time.Duration
	FetchTimeout time.Duration
}

// CIMDDocument represents a parsed Client ID Metadata Document.
type CIMDDocument struct {
	ClientID                string   `json:"client_id"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}
