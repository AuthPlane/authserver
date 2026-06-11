package input

import "time"

// ConnectionMeta is the operator-visible projection of a BrokerGrant
// returned by ConnectService.ListConnections (and re-exported by
// api/public/connection). It never carries credential bytes.
type ConnectionMeta struct {
	Provider      string    `json:"provider"`
	ScopesGranted []string  `json:"scopes_granted"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// CompleteConnectResult is returned by ConnectService.CompleteConnect for the
// callback handler to use when redirecting the user back to the operator app.
type CompleteConnectResult struct {
	Meta      ConnectionMeta
	ReturnURL string
}
