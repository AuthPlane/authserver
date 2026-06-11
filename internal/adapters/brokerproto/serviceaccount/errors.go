package serviceaccount

import "errors"

// errUpstreamHTTP is returned when the upstream token endpoint responds
// with a non-2xx status. Wrapping callers add the URL and truncated body
// for diagnostics. BrokerIssuer maps this to the caller-facing
// error surface.
var errUpstreamHTTP = errors.New("service_account upstream returned non-2xx status")

// errUpstreamMissingAccessToken is returned when the upstream responds
// 200 but the response body lacks a usable access_token field. Surfaced
// explicitly so we don't silently vend empty-string tokens.
var errUpstreamMissingAccessToken = errors.New("service_account upstream response missing access_token")

// errSAKeyLookup is returned when the SecretResolver cannot resolve the
// configured sa_key_env or the resolved value is not a usable PEM. Surfaced
// as its own sentinel so wiring code can distinguish missing-key-config
// from upstream failures.
var errSAKeyLookup = errors.New("service_account SA key lookup failed")
