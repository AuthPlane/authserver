package connectionapi

import (
	"net/url"
	"strings"
)

// ConsentURL builds the absolute URL a client should redirect to in order to
// start (or re-authorize) a Broker upstream-connection. The shape after
//
//	is `<base>/connect/<providerSlug>?resource=<resourceSlug>&return_url=<base>/connections`.
//
// providerSlug names the BrokerProvider (the AS-side identifier for the
// upstream OAuth client); resourceSlug names the originating Broker resource
// for forensic logging on the connect handler. When resourceSlug is empty
// (a defensive fallback — 's dispatchBroker always populates it), the
// `?resource=` parameter is omitted.
//
// This helper is the single source of truth for the public consent URL
// shape. Any change to the registered paths is caught by a single grep.
//
// Returns "" when base is empty. Callers should treat that as "no consent
// URL available" — the wire response still uses error code consent_required
// but omits the consent_url field (the DTO uses omitempty).
func ConsentURL(base, providerSlug, resourceSlug string) string {
	base = strings.TrimRight(base, "/")
	if base == "" {
		return ""
	}
	q := url.Values{}
	if resourceSlug != "" {
		q.Set("resource", resourceSlug)
	}
	q.Set("return_url", base+"/connections")
	return base + "/connect/" + providerSlug + "?" + q.Encode()
}

// ReconsentURL builds the URL a client should redirect to in order to
// re-consent at the AS for a Mint resource. Used for bound-B
// (agent-attestation row missing) and bound-C (agent-attestation scope
// insufficient) failures, where the remediation is the user re-running
// /authorize at the AS — NOT a re-connect at an upstream provider.
//
// Shape: `<base>/authorize?resource=<resourceSlug>&scope=<scope>`. When
// `scope` is empty the parameter is omitted. Both components are URL-
// escaped; an empty resourceSlug yields the same omission as ConsentURL's
// empty-providerSlug case (i.e. the path becomes `/authorize?` with no
// resource hint — the caller is expected to populate resourceSlug for
// any error that originated from dispatchBroker / dispatchMint).
//
// Returns "" when base is empty. Callers should treat that as "no consent
// URL available" — the wire response still uses error code consent_required
// but omits the consent_url field (the DTO uses omitempty).
func ReconsentURL(base, resourceSlug, scope string) string {
	base = strings.TrimRight(base, "/")
	if base == "" {
		return ""
	}
	q := url.Values{}
	if resourceSlug != "" {
		q.Set("resource", resourceSlug)
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	if len(q) == 0 {
		return base + "/authorize"
	}
	return base + "/authorize?" + q.Encode()
}
