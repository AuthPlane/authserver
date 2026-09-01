package output

import (
	"context"
	"time"
)

// XAAConfig is the per-request cross-app-access (RFC 7523 / jwt-bearer) config.
type XAAConfig struct {
	Enabled         bool
	TokenExpiry     time.Duration // TTL for XAA-issued access tokens
	MaxAssertionAge time.Duration // max age of ID-JAG iat
	RequireResource bool          // refuse exchanges naming no resource, on the assertion or the request
	SubjectMode     string        // "auto_map" or "strict"
	JWKSCacheTTL    time.Duration // JWKS cache TTL
}

// XAAConfigProvider supplies XAA config for a request.
type XAAConfigProvider interface {
	Config(ctx context.Context) (XAAConfig, error)
}
