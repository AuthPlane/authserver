// api/public/state_codec_test_helpers_test.go
//go:build integration

package public_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/ports/output"
)

// staticDCRModeForTest is an integration-test-local implementation of
// output.DCRModeProvider that returns fixed values for every call. It avoids
// importing internal/adapters/static from integration tests, which would
// violate Gate 0 (the one-way ratchet that forbids new internal/ imports in
// integration tests).
type staticDCRModeForTest struct {
	Mode              string
	ApprovedRedirects []string
}

func (p staticDCRModeForTest) Get(context.Context) (output.DCRMode, error) {
	return output.DCRMode{Mode: p.Mode, ApprovedRedirects: p.ApprovedRedirects}, nil
}

func (staticDCRModeForTest) Set(context.Context, output.DCRMode) error { return nil }

// staticStateCodecForTest mirrors the static.StateCodec wire format
// inline. Gate 0 forbids integration tests (//go:build integration)
// from importing internal/adapters/static, so this helper replicates
// the algorithm. Keep it byte-identical to static.StateCodec — if the
// production codec wire format changes, this helper must too.
type staticStateCodecForTest struct {
	key []byte
}

func newStateCodecForTest(key []byte) *staticStateCodecForTest {
	return &staticStateCodecForTest{key: append([]byte(nil), key...)}
}

func (c *staticStateCodecForTest) Encode(_ context.Context, s output.State) ([]byte, error) {
	ts := strconv.FormatInt(s.IssuedAt.UTC().Unix(), 10)
	payload5 := s.Redirect + "|" + s.Nonce + "|" + s.Verifier + "|" + s.BrowserNonce + "|" + ts
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(payload5))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return []byte(base64.RawURLEncoding.EncodeToString([]byte(payload5 + "|" + sig))), nil
}

func (c *staticStateCodecForTest) Decode(_ context.Context, b []byte) (output.State, error) {
	raw, err := base64.RawURLEncoding.DecodeString(string(b))
	if err != nil {
		return output.State{}, fmt.Errorf("decode: %w", err)
	}
	parts := strings.SplitN(string(raw), "|", 6)
	if len(parts) != 6 {
		return output.State{}, fmt.Errorf("expected 6 fields")
	}
	expected := func() string {
		mac := hmac.New(sha256.New, c.key)
		mac.Write([]byte(strings.Join(parts[:5], "|")))
		return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}()
	if !hmac.Equal([]byte(parts[5]), []byte(expected)) {
		return output.State{}, fmt.Errorf("sig mismatch")
	}
	ts, err := strconv.ParseInt(parts[4], 10, 64)
	if err != nil {
		return output.State{}, fmt.Errorf("bad ts: %w", err)
	}
	return output.State{
		Redirect:     parts[0],
		Nonce:        parts[1],
		Verifier:     parts[2],
		BrowserNonce: parts[3],
		IssuedAt:     time.Unix(ts, 0).UTC(),
	}, nil
}

// TestStaticStateCodecForTest_WireFormatPinned guards against drift between
// this hand-rolled helper and the production static.StateCodec. Gate 0 forbids
// importing internal/adapters/static here, so we pin the helper's output to a
// frozen vector that the production golden test (TestEncode_GoldenBytes in
// internal/adapters/static/state_codec_test.go) also asserts against, for the
// same key and input. If the production wire format changes, that test fails;
// if this helper drifts from it, this test fails. The two cannot diverge
// silently.
func TestStaticStateCodecForTest_WireFormatPinned(t *testing.T) {
	// key and input mirror goldenKeyDefault + goldenInputsDefault[0];
	// want mirrors goldenWireEncoded[0]. Keep all three in sync if the
	// production golden is regenerated.
	const (
		key  = "state-codec-test-key-do-not-use-in-production"
		want = "L2Rhc2hib2FyZHxuMXx2MXxiMXwxNzAwMDAwMDAwfGhoNmh3Qks1TG9FZHBBMWk2cTI0Q2tGMWUzMkJvc01ISGZWQVJuYzR6X0E"
	)
	codec := newStateCodecForTest([]byte(key))
	got, err := codec.Encode(context.Background(), output.State{
		Redirect:     "/dashboard",
		Nonce:        "n1",
		Verifier:     "v1",
		BrowserNonce: "b1",
		IssuedAt:     time.Unix(1700000000, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("helper encode: %v", err)
	}
	if string(got) != want {
		t.Errorf("integration helper wire format drifted from production golden:\n want %q\n got  %q", want, got)
	}
}
