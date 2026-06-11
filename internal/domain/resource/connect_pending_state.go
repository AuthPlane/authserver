package resource

import "time"

// ConnectPendingState is the ephemeral PKCE state recorded while a Broker
// connect flow is in flight. It is consumed once on callback and then
// deleted. Distinct from the legacy connection.PendingState shape: this type
// references a BrokerProvider (ProviderID) and a Resource (ResourceID) by
// FK rather than the old (OwnerID, Service) tuple. ReturnURL is validated
// at callback time against the target Resource's policy.connect.allowed_return_urls.
// See the architecture doc and the data model
type ConnectPendingState struct {
	ID           string
	UserID       string
	ProviderID   string
	ResourceID   string
	CodeVerifier string
	ReturnURL    string
	Scopes       []string
	ExpiresAt    time.Time
}

// IsExpired reports whether the state has passed its expiry timestamp.
// Callers compare against the same clock used to set ExpiresAt.
func (s *ConnectPendingState) IsExpired(now time.Time) bool {
	return !s.ExpiresAt.IsZero() && !now.Before(s.ExpiresAt)
}
