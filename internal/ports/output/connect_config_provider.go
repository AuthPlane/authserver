package output

import "context"

// ConnectConfig is the per-request upstream-connect flow config.
type ConnectConfig struct {
	AllowedReturnURLs []string // allowlist of post-connect return URLs
	RedirectBaseURL   string   // base URL for OAuth callbacks
}

// ConnectConfigProvider supplies connect-flow config for a request.
type ConnectConfigProvider interface {
	Config(ctx context.Context) (ConnectConfig, error)
}
