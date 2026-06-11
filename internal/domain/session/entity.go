// Package session contains the AuthSession domain entity.
// An AuthSession tracks the state of an in-flight authorization code grant.
package session

import "time"

// AuthSession holds the state between the authorize request and the token exchange.
// The auth code is stored hashed (SHA-256). PKCE challenge is stored as-is.
type AuthSession struct {
	ID                  string
	ClientID            string
	UserID              string
	RedirectURI         string
	Scope               string // space-separated granted scopes
	Resource            string // RFC 8707 resource indicator → JWT aud
	State               string // opaque state from client
	CodeHash            string // SHA-256 of the authorization code
	CodeChallenge       string // PKCE code_challenge (stored as-is)
	CodeChallengeMethod string // "S256"
	ExpiresAt           time.Time
	ConsumedAt          *time.Time
	CreatedAt           time.Time
}

// AuthCodeTTL is the maximum lifetime of an authorization code (10 minutes per spec).
const AuthCodeTTL = 10 * time.Minute

// IsExpired reports whether the authorization code has expired.
func (s *AuthSession) IsExpired() bool {
	return time.Now().UTC().After(s.ExpiresAt)
}

// IsConsumed reports whether the code has already been exchanged.
func (s *AuthSession) IsConsumed() bool {
	return s.ConsumedAt != nil
}

// Consume marks the code as used. Returns an error if already consumed.
func (s *AuthSession) Consume() error {
	if s.ConsumedAt != nil {
		return ErrAlreadyConsumed
	}
	now := time.Now().UTC()
	s.ConsumedAt = &now
	return nil
}

// ErrAlreadyConsumed is returned when trying to consume an already-consumed code.
var ErrAlreadyConsumed = &consumedError{}

type consumedError struct{}

func (e *consumedError) Error() string { return "authorization code has already been consumed" }
