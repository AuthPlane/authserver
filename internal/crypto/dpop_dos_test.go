package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/internal/domain"
)

// craftedRSAPrivateJWKProof returns a DPoP-shaped JWS whose protected header
// embeds an RSA "jwk" with a modulus of modulusBits bits plus the private
// parameters d, p and q. The values are random, so the key is not valid; that
// does not matter, because the expensive work happens while the header is
// parsed, before anything is verified.
func craftedRSAPrivateJWKProof(t *testing.T, modulusBits int) string {
	t.Helper()
	randomB64 := func(bits int) string {
		x, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
		if err != nil {
			t.Fatalf("random int: %v", err)
		}
		x.SetBit(x, bits-1, 1)
		// Odd values: an even p or q lets the parser bail out early, which
		// would make the cost depend on the random draw.
		x.SetBit(x, 0, 1)
		return base64.RawURLEncoding.EncodeToString(x.Bytes())
	}
	header, err := json.Marshal(map[string]any{
		"alg": "RS256",
		"typ": "dpop+jwt",
		"jwk": map[string]string{
			"kty": "RSA",
			"e":   "AQAB",
			"n":   randomB64(modulusBits),
			"d":   randomB64(modulusBits - 1),
			"p":   randomB64(modulusBits / 2),
			"q":   randomB64(modulusBits / 2),
		},
	})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(header) + ".e30.AAAA"
}

// Regression test for the go-jose header-JWK denial of service
// (CVE-2026-116587). go-jose up to v4.1.5 parses an embedded RSA "jwk" in full,
// including rsa.PrivateKey.Validate() when private parameters are present,
// before it checks anything else. The cost grows faster than the key size: on
// v4.1.5 this ~22 KB proof takes several seconds of CPU. v4.1.6 and later cap
// the modulus at 4096 bits and reject private parameters in a header jwk, so
// the same input fails in microseconds.
//
// The test calls the parse step directly, below the MaxDPoPProofBytes cap in
// ValidateProof, so it checks the library and not our own guard. It bounds the
// time rather than matching an error string: what matters is that the parse
// is cheap, not how it fails.
func TestParseDPoPProof_OversizedPrivateRSAHeaderJWK_RejectedQuickly(t *testing.T) {
	proof := craftedRSAPrivateJWKProof(t, 32768)

	requireRejectedWithin(t, "DPoP proof", proof, func(p string) error {
		_, err := parseDPoPProof(p)
		return err
	})
}

// The same crafted header reaches the parser through tokens that arrive in a
// form body (/oauth/revoke, /oauth/introspect, token exchange) and through
// jwt-bearer and ID-JAG assertions. Those paths are not covered by the header
// or DPoP size caps; only the library fix bounds them, so each parse entry
// point gets the same time-bounded check.
func TestJWTParseEntryPoints_OversizedPrivateRSAHeaderJWK_RejectedQuickly(t *testing.T) {
	token := craftedRSAPrivateJWKProof(t, 32768)
	empty := &jose.JSONWebKeySet{}

	t.Run("VerifyAccessToken", func(t *testing.T) {
		requireRejectedWithin(t, "access token", token, func(p string) error {
			_, err := VerifyAccessToken(p, empty)
			return err
		})
	})
	t.Run("ValidateIDJAG", func(t *testing.T) {
		requireRejectedWithin(t, "ID-JAG assertion", token, func(p string) error {
			_, err := ValidateIDJAG(p, empty, "https://as.example", time.Minute)
			return err
		})
	})
}

// requireRejectedWithin fails the test when parse accepts the input or takes
// longer than a second. On a vulnerable library the parse goroutine keeps
// running after the failure, until the test binary exits, so a timing failure
// here can slow the tests that run after it; read the first failure.
func requireRejectedWithin(t *testing.T, what, input string, parse func(string) error) {
	t.Helper()
	const budget = time.Second
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- parse(input) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("crafted %s parsed without error; want rejection", what)
		}
		t.Logf("rejected %d-byte %s in %v", len(input), what, time.Since(start))
	case <-time.After(budget):
		t.Fatalf("parsing a %d-byte %s with a crafted RSA header jwk took longer than %v: "+
			"the JOSE library is doing key-size-dependent work on untrusted input (CVE-2026-116587, go-jose < v4.1.6)",
			len(input), what, budget)
	}
}

// ValidateProof must refuse a proof larger than MaxDPoPProofBytes before it
// parses it, whatever the JOSE library would do with it. The proof here is
// otherwise valid (correctly signed, right htm/htu/iat), so only the size
// guard can reject it.
func TestValidateProof_OversizedProofRejected(t *testing.T) {
	key := mustGenerateES256Key(t)
	signer := mustNewSigner(t, key, jose.ES256)

	jti := strings.Repeat("j", MaxDPoPProofBytes)
	proof := mustCreateProof(t, signer, jti, testHTM, testHTU, time.Now(), "", "")
	if len(proof) <= MaxDPoPProofBytes {
		t.Fatalf("test proof is %d bytes; want it over the %d-byte cap", len(proof), MaxDPoPProofBytes)
	}

	_, err := ValidateProof(proof, testHTM, testHTU, "", "", testProofLifetime)
	if !errors.Is(err, domain.ErrDPoPInvalidProof) || !errors.Is(err, ErrDPoPProofTooLarge) {
		t.Fatalf("oversized proof: got %v, want ErrDPoPProofTooLarge wrapping ErrDPoPInvalidProof", err)
	}
}

// The cap must leave real proofs alone. The largest legitimate proof the
// server accepts is RS256 with a 4096-bit key (the parser's own ceiling)
// carrying both a nonce and an ath; it has to validate, and with room to spare.
func TestValidateProof_LargestLegitimateProofFitsUnderCap(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("generate 4096-bit RSA key: %v", err)
	}
	signer := mustNewSigner(t, key, jose.RS256)

	const nonce = "server-nonce-0123456789abcdefghijklmnopqrstuvwxyz0123456789"
	ath := ComputeATH(strings.Repeat("t", 2048))
	proof := mustCreateProof(t, signer, "jti-0123456789abcdef0123456789abcdef", testHTM, testHTU, time.Now(), nonce, ath)

	if len(proof) > MaxDPoPProofBytes/2 {
		t.Errorf("largest legitimate proof is %d bytes; want at most half the %d-byte cap", len(proof), MaxDPoPProofBytes)
	}
	if _, err := ValidateProof(proof, testHTM, testHTU, nonce, ath, testProofLifetime); err != nil {
		t.Fatalf("4096-bit RS256 proof with nonce and ath: %v", err)
	}
	t.Logf("4096-bit RS256 proof with nonce and ath: %d bytes", len(proof))
}
