// Package input defines the driving ports — what the outside world asks the system to do.
package input

import (
	"context"

	"github.com/authplane/authserver/internal/domain/session"
)

// AuthorizePort handles the authorization code flow.
type AuthorizePort interface {
	// StartAuthorization validates the authorize request and returns an auth session.
	// loginRequired is true if the user must authenticate first.
	// consentRequired is true if the user must approve scopes.
	StartAuthorization(ctx context.Context, req AuthorizeRequest) (*AuthorizeResult, error)

	// CompleteAuthorization finalizes the flow after login + consent,
	// generating the authorization code and returning redirect info.
	CompleteAuthorization(ctx context.Context, sessionID string) (*CompleteAuthResult, error)
}

// AuthorizeRequest contains the validated parameters from GET /oauth/authorize.
type AuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string // must be "code"
	Scope               string // space-separated
	State               string
	Resource            string // RFC 8707
	CodeChallenge       string // PKCE
	CodeChallengeMethod string // must be "S256"
	UserID              string // set by HTTP handler from session cookie; empty if not logged in
}

// AuthorizeResult is returned by StartAuthorization.
type AuthorizeResult struct {
	Session         *session.AuthSession
	LoginRequired   bool
	ConsentRequired bool
}

// CompleteAuthResult carries redirect info after authorization is finalized.
type CompleteAuthResult struct {
	RedirectURI string
	Code        string
	State       string
}
