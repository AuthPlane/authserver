package output

import (
	"context"
	"time"
)

// CIMDFetcher fetches and validates Client ID Metadata Documents.
type CIMDFetcher interface {
	// Fetch retrieves a CIMD from the given URL. The document is validated:
	// client_id must match the URL, required fields (redirect_uris, client_name)
	// must be present. The per-request cfg supplies the RequireHTTPS,
	// AllowPrivateAddresses, CacheTTL and FetchTimeout knobs — the fetcher holds
	// no policy of its own; the caller (the service, resolving the per-request
	// CIMDConfigProvider) is the single source of truth.
	Fetch(ctx context.Context, url string, cfg CIMDFetchConfig) (*CIMDDocument, error)
}

// CIMDFetchConfig holds the per-request knobs the fetcher honors. Enabled is not
// a fetch concern and is intentionally absent (the service gates on it before
// fetching).
type CIMDFetchConfig struct {
	// RequireHTTPS rejects non-HTTPS document URLs. It governs the scheme check
	// and nothing else — address filtering is a separate control.
	RequireHTTPS bool
	// AllowPrivateAddresses turns off address filtering, at both the URL-level
	// host check and the dial. With it set, a document URL may resolve to
	// loopback, RFC 1918 space or link-local including the cloud metadata
	// endpoint. For local development and tests pointing at httptest servers.
	// Cache entries are not shared between the two settings.
	AllowPrivateAddresses bool
	// CacheTTL bounds how long a fetched document is reused. The fetcher cache is
	// process-global and keyed by URL and address policy, so this is best-effort
	// across differing per-request values: the request that POPULATES an entry
	// stamps its lifetime, and a later request for the same URL gets that entry
	// until it expires regardless of its own CacheTTL (a shorter TTL is not
	// honored until the populating entry expires). Uniform under the OSS static
	// default.
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
