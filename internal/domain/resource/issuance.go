package resource

import "time"

// MaxAgentChainLength caps the depth of the agent_chain claim recorded on an
// Issuance. The cap matches internal/services/agent_identity.go's
// maxAgentChainLength so service-layer truncation and persisted issuances
// stay consistent.
const MaxAgentChainLength = 8

// Issuance is the per-token audit record. Every issued access token (Mint or
// Broker) writes one row. Single-audience: ResourceID names the one Resource
// the token is valid against. AgentID and AgentChain mirror the JWT claim
// shape declared in internal/crypto/jwt.go (AgentChain is
// shallowest-to-deepest [root, ..., leaf]); they are persisted for forensics.
// See the architecture doc and the data model
type Issuance struct {
	ID            string
	SubjectUserID string
	ClientID      string
	ResourceID    string
	Scopes        []string
	BackendKind   BackendKind
	Revocable     bool
	IssuedAt      time.Time
	ExpiresAt     time.Time
	RevokedAt     *time.Time
	JTI           string
	DPoPJKT       string
	AgentID       string
	AgentChain    []string

	// ConsentClientID is the client whose consent grant authorized this
	// mint — on a token exchange, the subject token's client, which is the
	// one the user faced at consent and the one the grant is keyed on.
	// ClientID above is the acting client, which on a cross-client
	// exchange is someone else. Empty when no consent gate ran: a fronted
	// exchange, where the operator's declaration stands in for consent, or
	// a grant with no user behind it. Consent revocation matches on this,
	// falling back to ClientID for rows written before it existed.
	ConsentClientID string
	// ParentJTI is the jti of the subject token this one was derived from.
	// Empty for a token that was not derived from another. Consent
	// revocation follows it transitively, so revoking the grant at the
	// root of a delegation chain reaches every hop below it.
	ParentJTI string
}

// IsRevoked reports whether the issuance has been revoked.
func (i *Issuance) IsRevoked() bool { return i.RevokedAt != nil }

// SetAgentChain assigns chain to AgentChain, truncating to
// MaxAgentChainLength entries if the input is longer. Truncation keeps the
// shallowest-to-deepest prefix [root, ..., MaxAgentChainLength-th actor],
// matching internal/services/agent_identity.go::AttachClaims.
func (i *Issuance) SetAgentChain(chain []string) {
	if len(chain) > MaxAgentChainLength {
		chain = chain[:MaxAgentChainLength]
	}
	i.AgentChain = chain
}
