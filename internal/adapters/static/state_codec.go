// internal/adapters/static/state_codec.go
package static

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/authplane/authserver/internal/ports/output"
)

// Compile-time conformance: StateCodec satisfies output.StateCodec.
var _ output.StateCodec = (*StateCodec)(nil)

// StateCodec encodes and decodes OAuth state values using an HMAC-SHA256 key
// resolved per call from an output.StateCodecConfigProvider. The wire format
// is two layers:
//
//	payload5 = redirect + "|" + nonce + "|" + verifier + "|" + browserNonce + "|" + ts
//	sig      = base64url(HMAC-SHA256(key, payload5))
//	wire     = base64url(payload5 + "|" + sig)
//
// where ts = state.IssuedAt.UTC().Unix() formatted as decimal. This reproduces
// the encoding previously inlined in the OIDC handler byte for byte.
//
// state.Extra is ignored on Encode and always nil on Decode — this
// implementation does not include Extra in the wire format.
//
// Wire-format limitation: '|' is the field separator. Field values containing
// '|' will not round-trip correctly. This is inherited from the pre-refactor
// inline encoding.
type StateCodec struct {
	config output.StateCodecConfigProvider
}

// NewStateCodec returns a codec that resolves its HMAC signing key per call
// from config. It performs no work at construction.
func NewStateCodec(config output.StateCodecConfigProvider) *StateCodec {
	return &StateCodec{config: config}
}

// Encode serializes state to URL-safe bytes ready to embed in the OAuth state
// query parameter. It resolves the signing key for the request, ignores
// state.Extra, and returns an error if the key cannot be resolved or is empty.
func (c *StateCodec) Encode(ctx context.Context, s output.State) ([]byte, error) {
	key, err := c.resolveKey(ctx)
	if err != nil {
		return nil, err
	}
	ts := strconv.FormatInt(s.IssuedAt.UTC().Unix(), 10)
	payload5 := s.Redirect + "|" + s.Nonce + "|" + s.Verifier + "|" + s.BrowserNonce + "|" + ts
	sig := sign(key, payload5)
	wire := base64.RawURLEncoding.EncodeToString([]byte(payload5 + "|" + sig))
	return []byte(wire), nil
}

// Decode parses URL-safe wire bytes back to State. It resolves the signing key
// for the request, then returns an error if the key is unavailable/empty, the
// bytes are not valid base64url, the inner blob does not split into 6 fields,
// the HMAC signature does not verify, or the timestamp is not a valid integer.
// Does NOT check freshness — that is the caller's responsibility.
func (c *StateCodec) Decode(ctx context.Context, b []byte) (output.State, error) {
	key, err := c.resolveKey(ctx)
	if err != nil {
		return output.State{}, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(string(b))
	if err != nil {
		return output.State{}, fmt.Errorf("state codec: base64 decode: %w", err)
	}
	parts := strings.SplitN(string(raw), "|", 6)
	if len(parts) != 6 {
		return output.State{}, fmt.Errorf("state codec: expected 6 fields, got %d", len(parts))
	}
	redirect, nonce, verifier, browserNonce, tsStr, gotSig :=
		parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]

	expectedSig := sign(key, redirect+"|"+nonce+"|"+verifier+"|"+browserNonce+"|"+tsStr)
	if !hmac.Equal([]byte(gotSig), []byte(expectedSig)) {
		return output.State{}, fmt.Errorf("state codec: signature mismatch")
	}

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return output.State{}, fmt.Errorf("state codec: invalid timestamp: %w", err)
	}

	return output.State{
		Redirect:     redirect,
		Nonce:        nonce,
		Verifier:     verifier,
		BrowserNonce: browserNonce,
		IssuedAt:     time.Unix(ts, 0).UTC(),
		// Extra: nil — this implementation never populates Extra
	}, nil
}

// key resolves the per-call signing key and rejects an empty one defensively,
// so an alternate provider cannot cause signing/verification with no key.
func (c *StateCodec) resolveKey(ctx context.Context) ([]byte, error) {
	cfg, err := c.config.Config(ctx)
	if err != nil {
		return nil, fmt.Errorf("state codec: resolve config: %w", err)
	}
	if len(cfg.Key) == 0 {
		return nil, fmt.Errorf("state codec: empty key")
	}
	return cfg.Key, nil
}

func sign(key []byte, payload string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
