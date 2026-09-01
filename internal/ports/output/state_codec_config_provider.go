package output

import "context"

// StateCodecConfig is the signing material used by a StateCodec.
type StateCodecConfig struct {
	// Key is the HMAC-SHA256 key used to sign and verify the OAuth state
	// payload. Must be non-empty.
	Key []byte
}

// StateCodecConfigProvider supplies the StateCodec signing material for a request.
type StateCodecConfigProvider interface {
	Config(ctx context.Context) (StateCodecConfig, error)
}
