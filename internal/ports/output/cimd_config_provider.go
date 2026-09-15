package output

import (
	"context"
	"time"
)

// CIMDConfig is the per-request client-ID-metadata-document config.
type CIMDConfig struct {
	Enabled               bool
	RequireHTTPS          bool
	AllowPrivateAddresses bool
	CacheTTL              time.Duration
	FetchTimeout          time.Duration
}

// CIMDConfigProvider supplies CIMD config for a request.
type CIMDConfigProvider interface {
	Config(ctx context.Context) (CIMDConfig, error)
}
