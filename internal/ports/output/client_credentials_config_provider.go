package output

import (
	"context"
	"time"
)

// ClientCredentialsConfig is the per-request client_credentials grant config.
type ClientCredentialsConfig struct {
	Enabled     bool
	TokenExpiry time.Duration // TTL for machine tokens (RFC 6749 §4.4)
}

// ClientCredentialsConfigProvider supplies client_credentials config for a request.
type ClientCredentialsConfigProvider interface {
	Config(ctx context.Context) (ClientCredentialsConfig, error)
}
