// internal/ports/output/state_codec.go
package output

import (
	"context"
	"time"
)

// State captures the OAuth `state` parameter payload carried across the
// /oidc/start and /oidc/callback round-trip. Callers populate the
// structural fields when minting; the codec serializes State to opaque,
// URL-safe bytes and back.
//
// Extra is a generic affordance for implementations that want to carry
// additional values (e.g., trace identifiers, audit correlation tokens)
// across the flow without modifying the base struct. The default
// implementation ignores Extra entirely.
type State struct {
	Redirect     string            // raw 'redirect' query param, used post-callback
	Nonce        string            // OIDC nonce echoed by the upstream IdP
	Verifier     string            // PKCE verifier matching the start-time challenge
	BrowserNonce string            // value pinned to the OIDC-state cookie
	IssuedAt     time.Time         // when the state was minted (used by handler for freshness)
	Extra        map[string]string // generic enrichments; implementation-defined treatment
}

// StateCodec serializes and deserializes OAuth State values.
//
// Encode returns URL-safe bytes that can be embedded directly in the
// OAuth `state` query parameter. On success, the returned slice MUST
// be non-nil and non-empty. Decode receives those same bytes and
// returns the original State, or an error if the payload was tampered
// with or otherwise malformed.
//
// Implementations MUST round-trip the structural fields (Redirect,
// Nonce, Verifier, BrowserNonce, IssuedAt). Treatment of Extra is
// implementation-defined. Implementations MAY use ctx to resolve
// per-request signing material; the default implementation ignores ctx.
//
// Decode MUST NOT validate freshness or any other request-level policy
// beyond integrity of the wire payload. Freshness, cookie binding, and
// redirect safety are the handler's responsibility.
type StateCodec interface {
	Encode(ctx context.Context, state State) ([]byte, error)
	Decode(ctx context.Context, b []byte) (State, error)
}
