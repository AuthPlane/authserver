package oauth

import "errors"

// errUpstreamHTTP is returned when the upstream token or revoke endpoint
// responds with a non-2xx status. The wrapping callers add the URL and
// truncated body for diagnostics. BrokerIssuer maps this to the
// caller-facing error surface.
var errUpstreamHTTP = errors.New("oauth upstream returned non-2xx status")

// errUpstreamMissingAccessToken is returned when the upstream responds 200
// but the response body lacks a usable access_token field. This is a
// protocol violation — surfaced explicitly so we don't silently vend
// empty-string tokens.
var errUpstreamMissingAccessToken = errors.New("oauth upstream response missing access_token")

// errSecretLookup is returned when the SecretResolver cannot resolve the
// configured client_secret_env. Surfaced as its own sentinel so wiring
// code can distinguish missing-secret-config from upstream failures.
var errSecretLookup = errors.New("oauth client secret lookup failed")
