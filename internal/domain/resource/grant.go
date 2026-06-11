package resource

import "time"

// ConsentGrant is the persisted record of a User → Agent per-Resource
// authorization. ClientID is always the Agent (the Client the user explicitly
// consented to). MCPs that act as the actor at /oauth/token never appear in
// this row — that semantic is enforced at the service layer.
// See the architecture doc and the data model
type ConsentGrant struct {
	ID         string
	UserID     string
	ClientID   string
	ResourceID string
	Scopes     []string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	RevokedAt  *time.Time
}

// IsRevoked reports whether the grant has been revoked.
func (g *ConsentGrant) IsRevoked() bool { return g.RevokedAt != nil }

// CoversScopes reports whether every requested scope is present in the
// granted set. An empty request set is trivially covered. Comparison is
// exact-match string equality on fine scope names.
func (g *ConsentGrant) CoversScopes(requested []string) bool {
	if len(requested) == 0 {
		return true
	}
	granted := make(map[string]struct{}, len(g.Scopes))
	for _, s := range g.Scopes {
		granted[s] = struct{}{}
	}
	for _, s := range requested {
		if _, ok := granted[s]; !ok {
			return false
		}
	}
	return true
}

// BrokerGrant is the persisted User → AS per-BrokerProvider credential.
// Keyed (user_id, broker_provider_id) so a single upstream connection covers
// every Resource that targets the same provider. CredentialData is encrypted
// bytes whose plaintext shape is owned by the BrokerProtocol adapter.
// ScopesGranted is in the upstream's wire format.
// See the architecture doc and the data model
type BrokerGrant struct {
	ID               string
	UserID           string
	BrokerProviderID string
	CredentialData   []byte
	ScopesGranted    []string
	EncBackend       string
	Version          int64
	CreatedAt        time.Time
	UpdatedAt        time.Time
	RevokedAt        *time.Time
}

// IsRevoked reports whether the grant has been revoked.
func (g *BrokerGrant) IsRevoked() bool { return g.RevokedAt != nil }
