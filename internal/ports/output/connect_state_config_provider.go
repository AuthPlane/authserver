package output

import "context"

// ConnectStateConfig is the signing material used to sign and verify the
// broker connect/disconnect state token.
type ConnectStateConfig struct {
	// Key is the HMAC-SHA256 key used to sign and verify the connect state
	// token payload. Must be non-empty.
	Key []byte
}

// ConnectStateConfigProvider supplies the connect-state signing material for a
// request.
//
// Implementations MUST return a key that is stable across the two requests of a
// single connect round-trip (/connect/start signs the state token, /connect/
// callback verifies it). A key that differs between those two calls breaks HMAC
// verification and surfaces as an invalid-state rejection. The default static
// provider returns a fixed key, so it is trivially consistent.
type ConnectStateConfigProvider interface {
	Config(ctx context.Context) (ConnectStateConfig, error)
}
