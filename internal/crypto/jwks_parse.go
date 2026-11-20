package crypto

import (
	"encoding/json"
	"errors"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// MaxSkippedJWKSample is how many skipped keys ParseJWKS describes one by
// one. A key source can publish thousands of unusable entries; the rest are
// only counted, so a hostile or broken JWKS cannot flood logs or errors.
const MaxSkippedJWKSample = 5

// maxSkippedFieldLen bounds the kid and kty copied from a skipped key.
const maxSkippedFieldLen = 128

// SkippedJWKs reports the keys ParseJWKS left out of the set: Total counts
// them all, Sample describes the first MaxSkippedJWKSample.
type SkippedJWKs struct {
	Total  int
	Sample []SkippedJWK
}

// SkippedJWK describes a key that ParseJWKS left out of the set.
type SkippedJWK struct {
	Index int    // position in the "keys" array
	Kid   string // the key's "kid", when it has one
	Kty   string // the key's "kty", when it has one
	Err   error  // why go-jose refused it
}

// ParseJWKS parses a JWK Set (RFC 7517 §5) one key at a time and returns the
// keys go-jose accepts, plus the ones it refused.
//
// json.Unmarshal into jose.JSONWebKeySet fails the whole set when any single
// key is refused. go-jose v4.1.6 and later refuse RSA keys whose modulus is
// over 4096 bits (jose.MaxRSAModulusBits), keys with an unsupported "kty",
// and certificate chains carrying such a key, so a single oversized key
// published next to normal ones would otherwise take every key of that
// issuer offline. RFC 7517 §5 says implementations SHOULD ignore keys they
// do not understand, which is what this does. Callers log the skipped keys.
// RSA keys over 4096 bits are skipped: AuthPlane leaves go-jose's
// MaxRSAModulusBits at 4096, since raising it would reopen the CPU cost
// that limit bounds.
//
// It fails when the document is not a JWK Set, or when the set had keys and
// none of them is usable.
func ParseJWKS(data []byte) (*jose.JSONWebKeySet, SkippedJWKs, error) {
	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, SkippedJWKs{}, fmt.Errorf("parse JWKS: %w", err)
	}

	set := &jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(raw.Keys))}
	var skipped SkippedJWKs
	for i, rk := range raw.Keys {
		var k jose.JSONWebKey
		if err := json.Unmarshal(rk, &k); err != nil {
			skipped.Total++
			if len(skipped.Sample) < MaxSkippedJWKSample {
				var hdr struct {
					Kid string `json:"kid"`
					Kty string `json:"kty"`
				}
				_ = json.Unmarshal(rk, &hdr)
				skipped.Sample = append(skipped.Sample, SkippedJWK{
					Index: i,
					Kid:   truncateField(hdr.Kid),
					Kty:   truncateField(hdr.Kty),
					Err:   err,
				})
			}
			continue
		}
		set.Keys = append(set.Keys, k)
	}

	if len(raw.Keys) > 0 && len(set.Keys) == 0 {
		errs := make([]error, 0, len(skipped.Sample)+1)
		for _, s := range skipped.Sample {
			errs = append(errs, fmt.Errorf("key %d (kid %q): %w", s.Index, s.Kid, s.Err))
		}
		if more := skipped.Total - len(skipped.Sample); more > 0 {
			errs = append(errs, fmt.Errorf("and %d more keys", more))
		}
		return nil, skipped, fmt.Errorf("parse JWKS: no usable key: %w", errors.Join(errs...))
	}
	return set, skipped, nil
}

func truncateField(s string) string {
	if len(s) <= maxSkippedFieldLen {
		return s
	}
	return s[:maxSkippedFieldLen] + "..."
}
