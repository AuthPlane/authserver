package client

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
)

const maxClientNameLength = 255
const maxRedirectURIs = 10
const maxAgentDescriptionLength = 255

// grantTypeEnvVars maps optional grant types to the env var that enables
// them at runtime. Used by ValidateCreateParams to surface a precise error
// when a client registers with a grant the AS isn't configured to honor —
// without this, registration succeeds and only fails hours later
// at /oauth/token with unsupported_grant_type. Grants not in this map
// (authorization_code, refresh_token) are always available and don't need
// a runtime gate.
//
//nolint:gosec // values are env-var names, not secrets — gosec's G101 misfires on the "_ENABLED" suffix.
var grantTypeEnvVars = map[string]string{
	"client_credentials":                              "AUTHPLANE_CLIENT_CREDENTIALS_ENABLED",
	"urn:ietf:params:oauth:grant-type:token-exchange": "AUTHPLANE_TOKEN_EXCHANGE_ENABLED",
	"urn:ietf:params:oauth:grant-type:jwt-bearer":     "AUTHPLANE_XAA_ENABLED",
}

// ValidateCreateParams validates the parameters for client registration.
//
// enabledGrants is the set of grant types the running AS is configured to
// honor (typically computed from config via config.EnabledGrantTypes).
// When non-nil, requests carrying a grant outside this set are rejected
// up-front with a message that names the env var the operator must set.
// A nil enabledGrants disables the check (used by tests that don't wire a
// full Config); production wiring always passes a populated set.
func ValidateCreateParams(p CreateParams, enabledGrants []string) error {
	var errs []string

	if strings.TrimSpace(p.Name) == "" {
		errs = append(errs, "client_name is required")
	} else if len(p.Name) > maxClientNameLength {
		errs = append(errs, fmt.Sprintf("client_name exceeds %d characters", maxClientNameLength))
	}

	if len(p.RedirectURIs) == 0 && requiresRedirectURI(p.GrantTypes) {
		errs = append(errs, "at least one redirect_uri is required")
	}
	if len(p.RedirectURIs) > maxRedirectURIs {
		errs = append(errs, fmt.Sprintf("too many redirect_uris (max %d)", maxRedirectURIs))
	}
	for _, uri := range p.RedirectURIs {
		if err := ValidateRedirectURI(uri); err != nil {
			errs = append(errs, err.Error())
		}
	}

	for _, gt := range p.GrantTypes {
		if err := ValidateGrantType(gt); err != nil {
			errs = append(errs, err.Error())
		}
	}
	errs = append(errs, checkGrantTypesEnabled(p.GrantTypes, enabledGrants)...)

	for _, rt := range p.ResponseTypes {
		if err := ValidateResponseType(rt); err != nil {
			errs = append(errs, err.Error())
		}
	}

	if p.TokenEndpointAuthMethod != "" {
		if err := ValidateAuthMethod(p.TokenEndpointAuthMethod); err != nil {
			errs = append(errs, err.Error())
		}
	}

	if len(p.AgentDescription) > maxAgentDescriptionLength {
		errs = append(errs, fmt.Sprintf("agent_description exceeds %d characters", maxAgentDescriptionLength))
	}

	if len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	return nil
}

// ValidateRedirectURI validates a single redirect URI.
// HTTPS required except for localhost (dev) per RFC 9700.
// No wildcards, no fragments.
func ValidateRedirectURI(uri string) error {
	parsed, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("redirect_uri %q is not a valid URL", uri)
	}

	if parsed.Fragment != "" {
		return fmt.Errorf("redirect_uri %q must not contain a fragment", uri)
	}

	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("redirect_uri %q must have scheme and host", uri)
	}

	// Allow http for localhost only
	if parsed.Scheme == "http" {
		host := parsed.Hostname()
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return fmt.Errorf("redirect_uri %q must use https (http allowed only for localhost)", uri)
		}
		return nil
	}

	if parsed.Scheme != "https" {
		return fmt.Errorf("redirect_uri %q must use https scheme", uri)
	}

	return nil
}

// ValidateGrantTypesEnabled rejects grant types that aren't in the
// runtime-enabled set. Returns nil when enabledGrants is nil (no
// enforcement — for tests/legacy callers without a Config), nil when
// every grant in grantTypes is enabled, or a *ValidationError naming the
// offending grants and the env vars that would enable them. Used by
// ValidateCreateParams (admin REST + DCR) and by the CIMD ingest path;
// kept exported so other client-creation seams can adopt the same
// fail-loud guarantee without re-running the whole validator.
func ValidateGrantTypesEnabled(grantTypes, enabledGrants []string) error {
	msgs := checkGrantTypesEnabled(grantTypes, enabledGrants)
	if len(msgs) == 0 {
		return nil
	}
	return &ValidationError{Errors: msgs}
}

// checkGrantTypesEnabled returns one human-readable error message per
// grant in grantTypes that isn't present in enabledGrants. Returns nil
// when enabledGrants is nil (back-compat skip).
func checkGrantTypesEnabled(grantTypes, enabledGrants []string) []string {
	if enabledGrants == nil {
		return nil
	}
	enabledSet := make(map[string]struct{}, len(enabledGrants))
	for _, gt := range enabledGrants {
		enabledSet[gt] = struct{}{}
	}

	var msgs []string
	for _, gt := range grantTypes {
		if _, ok := enabledSet[gt]; ok {
			continue
		}
		// Skip syntactically-bad grants — ValidateGrantType already
		// surfaces them; piling on a duplicate message would be noise.
		if ValidateGrantType(gt) != nil {
			continue
		}
		if envVar, optional := grantTypeEnvVars[gt]; optional {
			msgs = append(msgs, fmt.Sprintf(
				"grant_type %q is not enabled on this server — set %s=true to enable it",
				gt, envVar,
			))
		} else {
			msgs = append(msgs, fmt.Sprintf("grant_type %q is not enabled on this server", gt))
		}
	}
	return msgs
}

// validGrantTypes is every grant type the AS accepts on a client. It is a
// value rather than a switch so that callers which must classify grants —
// e.g. deciding whether a self-registered client keeps a user in the loop —
// can enumerate it and be tested for exhaustiveness against it. Adding a
// grant here without classifying it there is meant to fail a test, not to
// pick up a silent default.
var validGrantTypes = []string{
	"authorization_code",
	"refresh_token",
	"client_credentials",
	"urn:ietf:params:oauth:grant-type:token-exchange",
	"urn:ietf:params:oauth:grant-type:jwt-bearer",
}

// ValidGrantTypes returns every grant type the AS accepts on a client.
//
// A function over a copy, not an exported slice: this is the authoritative
// allowlist, and an exported var would let any package append to it or
// overwrite an entry. Enumerability is what the exhaustiveness test needs;
// write access is not, and the switch this replaced offered neither.
func ValidGrantTypes() []string {
	return slices.Clone(validGrantTypes)
}

// ValidateGrantType checks that the grant type is supported.
func ValidateGrantType(gt string) error {
	if slices.Contains(validGrantTypes, gt) {
		return nil
	}
	return fmt.Errorf("unsupported grant_type: %q", gt)
}

// ValidateResponseType checks that the response type is supported.
func ValidateResponseType(rt string) error {
	if rt != "code" {
		return fmt.Errorf("unsupported response_type: %q (only \"code\" is supported)", rt)
	}
	return nil
}

// ValidateAuthMethod checks the token endpoint auth method.
func ValidateAuthMethod(method string) error {
	switch method {
	case "none", "client_secret_basic", "client_secret_post":
		return nil
	default:
		return fmt.Errorf("unsupported token_endpoint_auth_method: %q", method)
	}
}

// ValidationError holds multiple validation errors.
type ValidationError struct {
	Errors []string
}

func (e *ValidationError) Error() string {
	return "client validation failed: " + strings.Join(e.Errors, "; ")
}

// requiresRedirectURI returns true if any of the grant types requires a redirect URI.
// client_credentials and token-exchange are server-to-server flows with no redirect.
func requiresRedirectURI(grantTypes []string) bool {
	for _, gt := range grantTypes {
		switch gt {
		case "authorization_code", "refresh_token":
			return true
		}
	}
	return false
}

// RedirectURIHost returns the host component of a redirect URI, for display on
// the consent screen. Empty when the URI does not parse or carries no host.
//
// The host is the only part of an authorization request the authorization
// server has actually verified — it was matched exactly against the client's
// registration. The client name beside it is self-declared and unverified, so
// on a screen where the user is being asked to make a trust decision, this is
// the field that carries a guarantee.
func RedirectURIHost(uri string) string {
	parsed, err := url.Parse(uri)
	if err != nil {
		return ""
	}
	return parsed.Host
}

// IsLoopbackRedirectURI reports whether a redirect URI sends the authorization
// code to the user's own machine.
//
// Deliberately broader than the http-scheme exemption in ValidateRedirectURI,
// which admits only the three literals it needs to: this drives a warning, and
// warning on one loopback address while staying silent on 127.0.0.5 would be
// the wrong way round. A DNS name that happens to resolve to a loopback address
// is not included — the address is not knowable here, and the specification's
// concern is a redirect that names the local machine on its face.
func IsLoopbackRedirectURI(uri string) bool {
	parsed, err := url.Parse(uri)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
