package crypto

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/token"
)

// assertionAlgorithms lists the asymmetric algorithms accepted for ID-JAG signatures.
// Symmetric algorithms (HS*) and alg:none are explicitly rejected.
var assertionAlgorithms = []jose.SignatureAlgorithm{
	jose.ES256, jose.ES384, jose.ES512,
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.EdDSA,
}

// AssertionAlgorithms returns the list of algorithms accepted for ID-JAG assertions.
func AssertionAlgorithms() []jose.SignatureAlgorithm {
	return assertionAlgorithms
}

// ValidateIDJAG parses and validates an ID-JAG (Identity Assertion Authorization
// Grant) JWT per RFC 7523 and the MCP Enterprise-Managed Authorization extension.
//
// Validation steps:
//  1. Parse as signed JWT — reject alg:none and HS* algorithms.
//  2. Verify typ header == "oauth-id-jag+jwt".
//  3. Verify signature against provided JWKS.
//  4. Validate exp (not expired, 30s clock skew).
//  5. Validate iat (not in future, not too old per maxAge).
//  6. Validate aud matches expectedAudience.
//  7. Validate iss, sub, client_id, jti are all non-empty.
func ValidateIDJAG(raw string, trustedKeys *jose.JSONWebKeySet, expectedAudience string, maxAge time.Duration) (*token.IdentityAssertion, error) {
	if raw == "" {
		return nil, fmt.Errorf("%w: empty assertion", domain.ErrAssertionInvalid)
	}

	// 1. Parse — only accept asymmetric algorithms.
	parsed, err := jose.ParseSigned(raw, assertionAlgorithms)
	if err != nil {
		// Check if the error is from an unsupported algorithm.
		if isAlgorithmError(raw) {
			return nil, fmt.Errorf("%w: symmetric or none algorithm not allowed", domain.ErrAssertionInvalid)
		}
		return nil, fmt.Errorf("%w: %v", domain.ErrAssertionInvalid, err)
	}

	// 2. Verify typ header.
	if len(parsed.Signatures) == 0 {
		return nil, fmt.Errorf("%w: missing signature", domain.ErrAssertionInvalid)
	}
	typ, _ := parsed.Signatures[0].Header.ExtraHeaders[jose.HeaderType].(string)
	if typ != "oauth-id-jag+jwt" {
		return nil, fmt.Errorf("%w: expected typ \"oauth-id-jag+jwt\", got %q", domain.ErrAssertionTypeMismatch, typ)
	}

	// 3. Verify signature against JWKS.
	kid := parsed.Signatures[0].Header.KeyID
	var payload []byte
	if kid != "" {
		keys := trustedKeys.Key(kid)
		if len(keys) == 0 {
			return nil, fmt.Errorf("%w: unknown key id %q", domain.ErrAssertionInvalid, kid)
		}
		payload, err = parsed.Verify(keys[0].Key)
	} else {
		// Try all keys in the JWKS.
		for i := range trustedKeys.Keys {
			payload, err = parsed.Verify(trustedKeys.Keys[i].Key)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%w: signature verification failed", domain.ErrAssertionInvalid)
	}

	// 4-7. Parse and validate claims.
	var claims token.IdentityAssertion
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: invalid claims JSON", domain.ErrAssertionInvalid)
	}

	now := time.Now().Unix()
	const clockSkew int64 = 30

	// 4. Validate exp.
	if claims.Expiry == 0 {
		return nil, fmt.Errorf("%w: missing exp claim", domain.ErrAssertionInvalid)
	}
	if now > claims.Expiry+clockSkew {
		return nil, fmt.Errorf("%w: assertion expired", domain.ErrAssertionExpired)
	}

	// 5. Validate iat.
	if claims.IssuedAt == 0 {
		return nil, fmt.Errorf("%w: missing iat claim", domain.ErrAssertionInvalid)
	}
	if claims.IssuedAt > now+clockSkew {
		return nil, fmt.Errorf("%w: iat is in the future", domain.ErrAssertionInvalid)
	}
	if maxAge > 0 {
		maxAgeUnix := now - int64(maxAge.Seconds())
		if claims.IssuedAt < maxAgeUnix {
			return nil, fmt.Errorf("%w: assertion too old (iat exceeds max age)", domain.ErrAssertionExpired)
		}
	}

	// 6. Validate aud.
	if claims.Audience == "" {
		return nil, fmt.Errorf("%w: missing aud claim", domain.ErrAssertionInvalid)
	}
	if claims.Audience != expectedAudience {
		return nil, fmt.Errorf("%w: expected %q, got %q", domain.ErrAssertionAudienceMismatch, expectedAudience, claims.Audience)
	}

	// 7. Validate required claims.
	if claims.Issuer == "" {
		return nil, fmt.Errorf("%w: missing iss claim", domain.ErrAssertionInvalid)
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("%w: missing sub claim", domain.ErrAssertionInvalid)
	}
	if claims.ClientID == "" {
		return nil, fmt.Errorf("%w: missing client_id claim", domain.ErrAssertionInvalid)
	}
	if claims.JTI == "" {
		return nil, fmt.Errorf("%w: missing jti claim", domain.ErrAssertionInvalid)
	}

	return &claims, nil
}

// isAlgorithmError inspects the raw JWT header to detect forbidden algorithms.
func isAlgorithmError(raw string) bool {
	parts := strings.SplitN(raw, ".", 3)
	if len(parts) < 2 {
		return false
	}
	// The jose library will reject none/HS* in ParseSigned when only asymmetric
	// algorithms are allowed, so this is a best-effort check for diagnostics.
	header := strings.ToLower(parts[0])
	return strings.Contains(header, `"none"`) ||
		strings.Contains(header, `"hs256"`) ||
		strings.Contains(header, `"hs384"`) ||
		strings.Contains(header, `"hs512"`)
}
