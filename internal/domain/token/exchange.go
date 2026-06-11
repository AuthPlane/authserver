package token

// Token type URN constants per RFC 8693 §3.
const (
	TokenTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token"  //nolint:gosec // not a credential, RFC 8693 URN identifier
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token" //nolint:gosec // not a credential, RFC 8693 URN identifier
	TokenTypeJWT          = "urn:ietf:params:oauth:token-type:jwt"           //nolint:gosec // not a credential, RFC 8693 URN identifier
)

// GrantTypeTokenExchange is the grant_type value for RFC 8693 token exchange.
const GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // not a credential, RFC 8693 grant type identifier

// IsValidSubjectTokenType returns true if the token type is a known URN for subject tokens.
func IsValidSubjectTokenType(tokenType string) bool {
	switch tokenType {
	case TokenTypeAccessToken, TokenTypeJWT:
		return true
	default:
		return false
	}
}

// ActClaim represents the delegation chain in an RFC 8693 §4.1 "act" claim.
// Each hop carries the acting party's subject, optionally a nested Act for
// multi-hop delegation chains, and Extras for any other identifying claims
// (e.g. client_id, iss, actor_type) that RFC 8693 §4.1 ¶1 permits inside an
// act object.
//
// Invariants this type enforces (do not break without reading RFC 8693 §4.1):
//
//  1. Identity claims only. Per §4.1 ¶2, non-identity/structural claims
//     (exp, nbf, aud, iat, jti) are "not meaningful" inside an act hop —
//     authserver MUST NOT stamp them. The ToMap/FromMap round-trip is lossless
//     and will pass such fields through defensively if they appear on the
//     wire, but no code path in this repo should add them.
//
//  2. Same-issuer trust assumption. Inner-hop Extras are only as trustworthy
//     as the issuer of the original subject token. Today authserver only
//     accepts its own tokens on the exchange path, so every inner-hop value
//     that exists was stamped by this server on a prior exchange. If
//     federation / cross-issuer subject tokens are ever added, revisit this:
//     a foreign issuer could stamp arbitrary Extras that authserver would then
//     pass through unverified.
//
//  3. Only the outermost actor is authoritative. Per §4.1 ¶6, consumers
//     MUST use only the top-level claims and the current (outermost) actor
//     for access-control decisions. Inner-hop metadata — including
//     actor_type — is informational (display, audit) and MUST NOT influence
//     authorization.
type ActClaim struct {
	Sub string    `json:"sub"`
	Act *ActClaim `json:"act,omitempty"` // nested for multi-hop
	// Extras carries additional identifying claims present on this hop
	// beyond sub/act. Populated by ActClaimFromMap from the incoming act
	// object, or by the server when stamping a new hop (e.g. actor_type).
	// Round-tripped via ToMap/FromMap rather than struct tags so it can hold
	// arbitrary JSON-compatible values. Nil when no extra fields exist.
	Extras map[string]interface{} `json:"-"`
}

// nonIdentityClaimKeys are JWT structural/temporal claims that RFC 8693
// §4.1 ¶2 declares "not meaningful" inside an act hop. authserver never
// stamps them and strips any that appear on an inbound inner hop.
var nonIdentityClaimKeys = []string{"exp", "nbf", "aud", "iat", "jti"}

// SanitizeNonIdentityClaims walks the delegation chain and removes the
// non-identity claims listed in RFC 8693 §4.1 ¶2 from every hop's Extras.
// Mutates in place and returns the receiver for chaining. Safe on nil.
//
// This enforces RFC compliance actively rather than relying on the
// runtime invariant that the only subject tokens authserver accepts today
// are its own. When federation is added and cross-issuer subject tokens
// become possible, this function is the single point that prevents a
// foreign issuer from stuffing structural claims into an inner act hop.
func (a *ActClaim) SanitizeNonIdentityClaims() *ActClaim {
	for hop := a; hop != nil; hop = hop.Act {
		if hop.Extras == nil {
			continue
		}
		for _, k := range nonIdentityClaimKeys {
			delete(hop.Extras, k)
		}
		if len(hop.Extras) == 0 {
			hop.Extras = nil
		}
	}
	return a
}

// Depth counts the nesting levels in the delegation chain.
// A single ActClaim with no nested act has depth 1.
// Returns 0 for nil receiver.
func (a *ActClaim) Depth() int {
	if a == nil {
		return 0
	}
	return 1 + a.Act.Depth()
}

// ActClaimToMap converts an ActClaim to a map for embedding in JWT claims.
// Extras are copied in first; sub/act are written afterwards so they cannot
// be spoofed by a caller that placed "sub" or "act" inside Extras.
func ActClaimToMap(a *ActClaim) map[string]interface{} {
	if a == nil {
		return nil
	}
	m := make(map[string]interface{}, len(a.Extras)+2)
	for k, v := range a.Extras {
		m[k] = v
	}
	m["sub"] = a.Sub
	if a.Act != nil {
		m["act"] = ActClaimToMap(a.Act)
	} else {
		// Ensure Extras cannot smuggle an "act" past a nil nested chain.
		delete(m, "act")
	}
	return m
}

// ActClaimFromMap reconstructs an ActClaim from a map (e.g. parsed from JWT
// claims). Every key other than "sub" and "act" is preserved in Extras so
// the round-trip is lossless per RFC 8693 §4.1 ¶1. Returns nil if m is nil.
func ActClaimFromMap(m map[string]interface{}) *ActClaim {
	if m == nil {
		return nil
	}
	a := &ActClaim{}
	if sub, ok := m["sub"].(string); ok {
		a.Sub = sub
	}
	// Per RFC 8693 §4.1, "act" MUST be a JSON object. A non-object value is
	// malformed and intentionally dropped here rather than preserved in
	// Extras — we will not round-trip RFC-invalid input.
	if nested, ok := m["act"].(map[string]interface{}); ok {
		a.Act = ActClaimFromMap(nested)
	}
	for k, v := range m {
		if k == "sub" || k == "act" {
			continue
		}
		if a.Extras == nil {
			a.Extras = make(map[string]interface{})
		}
		a.Extras[k] = v
	}
	return a
}
