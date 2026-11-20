package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

// oversizedRSAPublicJWK returns a public RSA JWK whose modulus has the given
// bit length. Only the length matters to go-jose's size check, so the modulus
// is random rather than a real product of primes (generating a real 8192-bit
// key takes seconds).
func oversizedRSAPublicJWK(t *testing.T, kid string, bits int) json.RawMessage {
	t.Helper()
	n := make([]byte, bits/8)
	if _, err := rand.Read(n); err != nil {
		t.Fatal(err)
	}
	n[0] |= 0x80
	n[len(n)-1] |= 0x01
	return json.RawMessage(fmt.Sprintf(`{"kty":"RSA","kid":%q,"use":"sig","alg":"RS256","n":%q,"e":"AQAB"}`,
		kid, base64.RawURLEncoding.EncodeToString(n)))
}

func publicJWK(t *testing.T, kid string, key any, alg jose.SignatureAlgorithm) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: string(alg), Use: "sig"})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func jwksDoc(t *testing.T, keys ...json.RawMessage) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseJWKS_SkipsOversizedRSAKeyAndKeepsTheRest(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc := jwksDoc(t,
		publicJWK(t, "rsa-2048", &rsaKey.PublicKey, jose.RS256),
		oversizedRSAPublicJWK(t, "rsa-8192", 8192),
		publicJWK(t, "ec-p256", &ecKey.PublicKey, jose.ES256),
	)

	// The plain go-jose path refuses the whole set; that is the regression
	// this parser exists to avoid.
	var whole jose.JSONWebKeySet
	if wholeErr := json.Unmarshal(doc, &whole); wholeErr == nil {
		t.Fatal("expected go-jose to refuse a set with an 8192-bit RSA key; if it no longer does, ParseJWKS may be unnecessary")
	}

	set, skipped, err := ParseJWKS(doc)
	if err != nil {
		t.Fatalf("ParseJWKS: %v", err)
	}
	if got := len(set.Keys); got != 2 {
		t.Fatalf("got %d keys, want 2", got)
	}
	if len(set.Key("rsa-2048")) != 1 || len(set.Key("ec-p256")) != 1 {
		t.Fatalf("usable keys missing: %+v", set.Keys)
	}
	if skipped.Total != 1 || len(skipped.Sample) != 1 || skipped.Sample[0].Kid != "rsa-8192" || skipped.Sample[0].Kty != "RSA" || skipped.Sample[0].Index != 1 || skipped.Sample[0].Err == nil {
		t.Fatalf("skipped = %+v, want the 8192-bit key at index 1", skipped)
	}
}

func TestParseJWKS_SkipsUnknownKeyType(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc := jwksDoc(t,
		json.RawMessage(`{"kty":"XYZ","kid":"future"}`),
		publicJWK(t, "ec-p256", &ecKey.PublicKey, jose.ES256),
	)
	set, skipped, err := ParseJWKS(doc)
	if err != nil {
		t.Fatalf("ParseJWKS: %v", err)
	}
	if len(set.Keys) != 1 || skipped.Total != 1 || skipped.Sample[0].Kid != "future" {
		t.Fatalf("keys=%d skipped=%+v", len(set.Keys), skipped)
	}
}

func TestParseJWKS_FailsWhenNoKeyIsUsable(t *testing.T) {
	doc := jwksDoc(t, oversizedRSAPublicJWK(t, "big-1", 8192), oversizedRSAPublicJWK(t, "big-2", 6144))
	_, skipped, err := ParseJWKS(doc)
	if err == nil {
		t.Fatal("expected an error when every key is refused")
	}
	if skipped.Total != 2 || !strings.Contains(err.Error(), "big-1") || !strings.Contains(err.Error(), "no usable key") {
		t.Fatalf("err=%v skipped=%+v", err, skipped)
	}
}

func TestParseJWKS_RejectsNonJWKSDocument(t *testing.T) {
	for _, doc := range []string{`not json`, `{"keys":"nope"}`, `[1,2]`} {
		if _, _, err := ParseJWKS([]byte(doc)); err == nil {
			t.Errorf("ParseJWKS(%q): expected error", doc)
		}
	}
}

func TestParseJWKS_EmptySetIsNotAnError(t *testing.T) {
	// Same as json.Unmarshal into jose.JSONWebKeySet: an empty set parses,
	// and the caller's kid lookup reports the missing key.
	for _, doc := range []string{`{"keys":[]}`, `{}`} {
		set, skipped, err := ParseJWKS([]byte(doc))
		if err != nil || len(set.Keys) != 0 || skipped.Total != 0 {
			t.Errorf("ParseJWKS(%q) = %d keys, %d skipped, err %v", doc, len(set.Keys), skipped.Total, err)
		}
	}
}

func TestParseJWKS_BoundsWhatItReportsAboutSkippedKeys(t *testing.T) {
	const n = 1000
	longKid := strings.Repeat("k", 10_000)
	keys := make([]json.RawMessage, n)
	for i := range keys {
		keys[i] = json.RawMessage(`{"kty":"future","kid":"` + longKid + `"}`)
	}
	doc, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}

	_, skipped, err := ParseJWKS(doc)
	if err == nil {
		t.Fatal("expected an error for a set with no usable key")
	}
	if skipped.Total != n {
		t.Fatalf("Total = %d, want %d", skipped.Total, n)
	}
	if len(skipped.Sample) != MaxSkippedJWKSample {
		t.Fatalf("len(Sample) = %d, want %d", len(skipped.Sample), MaxSkippedJWKSample)
	}
	for _, s := range skipped.Sample {
		if len(s.Kid) > maxSkippedFieldLen+len("...") {
			t.Fatalf("kid not truncated: %d bytes", len(s.Kid))
		}
	}
	if len(err.Error()) > 4096 {
		t.Fatalf("error is %d bytes; it must stay bounded however many keys were skipped", len(err.Error()))
	}
	if !strings.Contains(err.Error(), "and 995 more keys") {
		t.Fatalf("error does not count the undescribed keys: %v", err)
	}
}
