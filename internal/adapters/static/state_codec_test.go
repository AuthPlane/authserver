package static_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/ports/output"
)

// codecFor builds a StateCodec keyed with a fixed key, via the default provider.
func codecFor(key []byte) *static.StateCodec {
	return static.NewStateCodec(static.NewStateCodecConfigProvider(key))
}

// stubKeyProvider is a test StateCodecConfigProvider returning a fixed config or error.
type stubKeyProvider struct {
	cfg output.StateCodecConfig
	err error
}

func (s stubKeyProvider) Config(context.Context) (output.StateCodecConfig, error) {
	return s.cfg, s.err
}

// NOTE: This file declares its own goldenKeyDefault, goldenInputsDefault,
// goldenInputDefault, and goldenWireEncoded at the bottom (used by
// TestEncode_GoldenBytes). The companion file golden_gen_test.go declares
// unsuffixed goldenKey, goldenInputs, goldenInput names gated by the
// //go:build regen tag, so the two files coexist in the same package without
// symbol collision. If you change inputs in one file, sync the other (both
// must agree to keep TestEncode_GoldenBytes passing against the inline golden).

func TestEncode_GoldenBytes(t *testing.T) {
	codec := codecFor(goldenKeyDefault)

	if len(goldenWireEncoded) != len(goldenInputsDefault) {
		t.Fatalf("goldenWireEncoded has %d entries but goldenInputsDefault has %d — keep them in sync",
			len(goldenWireEncoded), len(goldenInputsDefault))
	}

	for i, in := range goldenInputsDefault {
		s := output.State{
			Redirect:     in.redirect,
			Nonce:        in.nonce,
			Verifier:     in.verifier,
			BrowserNonce: in.browser,
			IssuedAt:     time.Unix(in.tsUnix, 0).UTC(),
		}
		got, err := codec.Encode(context.Background(), s)
		if err != nil {
			t.Fatalf("encode [%d] %+v: %v", i, in, err)
		}
		if string(got) != goldenWireEncoded[i] {
			t.Errorf("[%d] encoded bytes differ from golden — wire format may have shifted.\n golden: %q\n got:    %q",
				i, goldenWireEncoded[i], got)
		}
	}
}

func TestEncode_Decode_RoundTrip(t *testing.T) {
	codec := codecFor([]byte("test-key-anything-non-empty"))
	in := output.State{
		Redirect:     "/dashboard",
		Nonce:        "nonce-value",
		Verifier:     "verifier-value",
		BrowserNonce: "browser-nonce",
		IssuedAt:     time.Unix(1700000000, 0).UTC(),
	}
	wire, err := codec.Encode(context.Background(), in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, err := codec.Decode(context.Background(), wire)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Redirect != in.Redirect || out.Nonce != in.Nonce ||
		out.Verifier != in.Verifier || out.BrowserNonce != in.BrowserNonce ||
		!out.IssuedAt.Equal(in.IssuedAt) {
		t.Errorf("roundtrip mismatch:\n in=%+v\nout=%+v", in, out)
	}
	if out.Extra != nil {
		t.Errorf("expected Extra=nil from default codec, got %v", out.Extra)
	}
}

func TestEncode_IgnoresExtra(t *testing.T) {
	codec := codecFor([]byte("test-key-anything-non-empty"))
	withoutExtra := output.State{Redirect: "/", IssuedAt: time.Unix(1700000000, 0).UTC()}
	withExtra := withoutExtra
	withExtra.Extra = map[string]string{"any": "value"}

	a, _ := codec.Encode(context.Background(), withoutExtra)
	b, _ := codec.Encode(context.Background(), withExtra)
	if !bytes.Equal(a, b) {
		t.Errorf("Extra must not affect default codec wire bytes\na=%s\nb=%s", a, b)
	}
}

func TestDecode_BadBase64_ReturnsError(t *testing.T) {
	codec := codecFor([]byte("test-key-anything-non-empty"))
	_, err := codec.Decode(context.Background(), []byte("not!valid!base64!"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "base64") {
		t.Errorf("expected base64-related error, got: %v", err)
	}
}

func TestDecode_FieldCountMismatch_ReturnsError(t *testing.T) {
	codec := codecFor([]byte("test-key-anything-non-empty"))
	// "only|three|fields" wrapped in base64 — splits to 3 parts, not 6
	bad := []byte("b25seXx0aHJlZXxmaWVsZHM") // base64url("only|three|fields")
	_, err := codec.Decode(context.Background(), bad)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "6 fields") {
		t.Errorf("expected field-count error, got: %v", err)
	}
}

func TestDecode_SignatureMismatch_ReturnsError(t *testing.T) {
	codec1 := codecFor([]byte("key-one"))
	codec2 := codecFor([]byte("key-two")) // different key
	in := output.State{
		Redirect: "/", Nonce: "n", Verifier: "v", BrowserNonce: "b",
		IssuedAt: time.Unix(1700000000, 0).UTC(),
	}
	wire, _ := codec1.Encode(context.Background(), in)
	_, err := codec2.Decode(context.Background(), wire)
	if err == nil {
		t.Fatal("expected sig mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("expected signature error, got: %v", err)
	}
}

func TestDecode_InvalidTimestamp_ReturnsError(t *testing.T) {
	key := []byte("test-key-anything-non-empty")
	codec := codecFor(key)

	corrupt := corruptTimestamp(t, key)

	_, err := codec.Decode(context.Background(), corrupt)
	if err == nil {
		t.Fatal("expected timestamp error, got nil")
	}
	if !strings.Contains(err.Error(), "timestamp") {
		t.Errorf("expected timestamp error, got: %v", err)
	}
}

// corruptTimestamp builds a wire blob with timestamp = "not-a-number"
// and re-signs so HMAC verification passes but timestamp parsing fails.
// Mirrors the codec's sign algorithm inline because the sign helper is unexported.
func corruptTimestamp(t *testing.T, key []byte) []byte {
	t.Helper()
	payload5 := "/" + "|" + "n" + "|" + "v" + "|" + "b" + "|" + "not-a-number"
	mac := hmacSHA256(key, []byte(payload5))
	sig := base64URL(mac)
	return []byte(base64URL([]byte(payload5 + "|" + sig)))
}

func TestStateCodec_ConfigError_Propagates(t *testing.T) {
	codec := static.NewStateCodec(stubKeyProvider{err: errKeyBoom})
	in := output.State{IssuedAt: time.Unix(1700000000, 0).UTC()}
	if _, err := codec.Encode(context.Background(), in); err == nil {
		t.Fatal("Encode: expected config error")
	}
	// input irrelevant; key resolution fails before base64 decode is attempted
	if _, err := codec.Decode(context.Background(), []byte("anything")); err == nil {
		t.Fatal("Decode: expected config error")
	}
}

func TestStateCodec_EmptyKey_Errors(t *testing.T) {
	codec := static.NewStateCodec(stubKeyProvider{cfg: output.StateCodecConfig{Key: nil}})
	in := output.State{IssuedAt: time.Unix(1700000000, 0).UTC()}
	if _, err := codec.Encode(context.Background(), in); err == nil {
		t.Fatal("Encode: expected empty-key error")
	}
	if _, err := codec.Decode(context.Background(), []byte("anything")); err == nil {
		t.Fatal("Decode: expected empty-key error")
	}
}

var errKeyBoom = errors.New("key boom")

// goldenKeyDefault, goldenInputsDefault, hmacSHA256, base64URL are
// helpers used by the default-build test functions above. The same-named
// values in golden_gen_test.go are scoped to the regen build tag so the
// two files don't collide.
var goldenKeyDefault = []byte("state-codec-test-key-do-not-use-in-production")

type goldenInputDefault struct {
	redirect, nonce, verifier, browser string
	tsUnix                             int64
}

var goldenInputsDefault = []goldenInputDefault{
	{redirect: "/dashboard", nonce: "n1", verifier: "v1", browser: "b1", tsUnix: 1700000000},
	{redirect: "/", nonce: "n2", verifier: "v2", browser: "b2", tsUnix: 1700000060},
	{redirect: "/admin?x=1", nonce: "n3", verifier: "v3", browser: "b3", tsUnix: 1700000120},
	{redirect: "/path%20with%20space", nonce: "n4", verifier: "v4", browser: "b4", tsUnix: 1700000180},
	{redirect: "/x", nonce: "n5", verifier: "v5", browser: "b5", tsUnix: 1700000240},
}

// goldenWireEncoded holds the bytes-for-byte expected Encode output for
// each goldenInputsDefault entry, captured from the pre-refactor inline
// encoding algorithm. These values are the byte-identity contract — a
// mismatch in TestEncode_GoldenBytes means the wire format has shifted.
//
// To regenerate (only when the wire format intentionally changes):
//
//	go test -tags=regen -run TestPrintGoldenForCopyPaste ./internal/adapters/static/
//
// Then copy the printed strings into the slice below in goldenInputsDefault order.
var goldenWireEncoded = []string{
	"L2Rhc2hib2FyZHxuMXx2MXxiMXwxNzAwMDAwMDAwfGhoNmh3Qks1TG9FZHBBMWk2cTI0Q2tGMWUzMkJvc01ISGZWQVJuYzR6X0E",
	"L3xuMnx2MnxiMnwxNzAwMDAwMDYwfDRWOWpUc25fcVZneHBDS2NIdXM4T25FZlVYV1ZIUVJzQzNVUWlUQVluUlE",
	"L2FkbWluP3g9MXxuM3x2M3xiM3wxNzAwMDAwMTIwfGRKblZhd2poX19aanRqSERaWldCWGl6clNPeTRCZW1UdVg2RzdfdVJXdzA",
	"L3BhdGglMjB3aXRoJTIwc3BhY2V8bjR8djR8YjR8MTcwMDAwMDE4MHw1X3JzMThSRVVldlczTmpRMlUzNTQzNXU5YVFVUTVzOFhGY19jMEZOQ3Vr",
	"L3h8bjV8djV8YjV8MTcwMDAwMDI0MHxHbnd3T1ROdEdqcjBOeHZodk85dlY2TGFWX281aE5Tb2VCU0RMVTEwWnFz",
}

func hmacSHA256(key, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return mac.Sum(nil)
}

func base64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
