package resource

import "time"

// BrokerProvider is an upstream OAuth app (or equivalent) registration
// shared by every Broker Resource that targets the same upstream. See
// the architecture doc and the resource-unification design
//
// ConfigData is the raw JSON shape owned by the BrokerProtocol adapter
// for this provider's Protocol. The core code never parses it; the
// adapter does.
type BrokerProvider struct {
	ID          string
	Slug        string
	DisplayName string
	Protocol    Protocol
	ConfigData  []byte
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Protocol is the wire protocol the AS speaks to the upstream provider.
// It also names the BrokerProtocol adapter that handles this provider.
type Protocol string

const (
	ProtocolOAuth          Protocol = "oauth"
	ProtocolAPIKey         Protocol = "api_key"
	ProtocolServiceAccount Protocol = "service_account"
)
