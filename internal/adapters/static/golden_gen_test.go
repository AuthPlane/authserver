//go:build regen

// Run with: go test -tags=regen -run TestPrintGoldenForCopyPaste ./internal/adapters/static/
//
// This helper reproduces the pre-refactor inline OAuth state encoding
// (HMAC-SHA256 over '|'-joined 5 fields, sig is base64url, outer wrap
// is base64url) and prints the result as Go-syntax strings ready to
// paste into the goldenWireEncoded slice in state_codec_test.go.
//
// goldenKey and goldenInputs MUST stay in sync with goldenKeyDefault
// and goldenInputsDefault in state_codec_test.go (or copy-paste output
// will diverge from what TestEncode_GoldenBytes expects).
//
// NEVER edit the algorithm here without confirming the change is
// intentional AND a fresh capture has been pasted into the test file.

package static_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"testing"
)

var goldenKey = []byte("state-codec-test-key-do-not-use-in-production")

type goldenInput struct {
	redirect, nonce, verifier, browser string
	tsUnix                             int64
}

var goldenInputs = []goldenInput{
	{redirect: "/dashboard", nonce: "n1", verifier: "v1", browser: "b1", tsUnix: 1700000000},
	{redirect: "/", nonce: "n2", verifier: "v2", browser: "b2", tsUnix: 1700000060},
	{redirect: "/admin?x=1", nonce: "n3", verifier: "v3", browser: "b3", tsUnix: 1700000120},
	{redirect: "/path%20with%20space", nonce: "n4", verifier: "v4", browser: "b4", tsUnix: 1700000180},
	{redirect: "/x", nonce: "n5", verifier: "v5", browser: "b5", tsUnix: 1700000240},
}

// encodeWirePrePatch reproduces the inline encoding from
// api/public/oauth/oidc.go signState + base64 wrap (pre-refactor).
// Keep this byte-identical to the production code at the time of golden capture.
func encodeWirePrePatch(key []byte, in goldenInput) []byte {
	ts := strconv.FormatInt(in.tsUnix, 10)
	payload5 := in.redirect + "|" + in.nonce + "|" + in.verifier + "|" + in.browser + "|" + ts
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload5))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	wire := base64.RawURLEncoding.EncodeToString([]byte(payload5 + "|" + sig))
	return []byte(wire)
}

func TestPrintGoldenForCopyPaste(t *testing.T) {
	t.Log("Copy the following entries into goldenWireEncoded in state_codec_test.go:")
	for _, in := range goldenInputs {
		t.Logf("\t%q,", string(encodeWirePrePatch(goldenKey, in)))
	}
}
