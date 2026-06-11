package input

import "context"

// ConsentPort manages user consent for OAuth flows.
type ConsentPort interface {
	// GetPendingConsent returns the consent view for a pending authorization session.
	GetPendingConsent(ctx context.Context, sessionID string) (*ConsentView, error)

	// GrantConsent records the user's approval and returns the updated session.
	GrantConsent(ctx context.Context, req GrantConsentRequest) (*GrantConsentResult, error)

	// DenyConsent records the user's denial of consent. userID is the
	// currently-authenticated subject and MUST match the session owner —
	// otherwise an arbitrary logged-in user could abort another user's
	// pending flow by knowing the session_id.
	DenyConsent(ctx context.Context, sessionID, userID string) error
}

// ConsentView contains the information to render the consent screen.
//
// ResourceDisplayName is the operator-friendly name shown in the per-MCP
// header ("<ClientName> wants permission to access <ResourceDisplayName>").
// Falls back to ResourceSlug when DisplayName is empty, then to Resource
// (URI). ResourceSlug is the audit-friendly identifier rendered in the
// resource pill below the header. Both are populated by the consent
// service from the resolved resource.
type ConsentView struct {
	SessionID           string
	ClientName          string
	ClientID            string
	Resource            string
	ResourceDisplayName string
	ResourceSlug        string
	Scopes              []ScopeInfo
}

// ScopeInfo describes a single scope for the consent screen.
type ScopeInfo struct {
	Name        string
	Description string
}

// GrantConsentRequest records which scopes the user approved.
type GrantConsentRequest struct {
	SessionID      string
	UserID         string
	ApprovedScopes []string
	Remember       bool // if true, persist consent for future requests
}

// GrantConsentResult is returned after consent is granted.
type GrantConsentResult struct {
	RedirectURI string
	Code        string
	State       string
}
