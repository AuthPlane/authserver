package output

import "context"

// CIMDFetcher fetches and validates Client ID Metadata Documents.
type CIMDFetcher interface {
	// Fetch retrieves a CIMD from the given URL.
	// The document is validated: client_id must match the URL,
	// required fields (redirect_uris, client_name) must be present.
	Fetch(ctx context.Context, url string) (*CIMDDocument, error)
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
