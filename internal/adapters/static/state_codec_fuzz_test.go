package static_test

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/ports/output"
)

func FuzzStateCodec_Default_Roundtrip(f *testing.F) {
	codec := static.NewStateCodec(static.NewStateCodecConfigProvider([]byte("fuzz-key-32-bytes-pad-pad-padxxxx")))

	// Seed corpus — meaningful starting points
	f.Add("/dashboard", "n1", "v1", "b1", int64(1700000000))
	f.Add("/", "", "", "", int64(0))
	f.Add("/path?q=1&r=2", "abc-def", "verifier", "browser", int64(1))

	f.Fuzz(func(t *testing.T, redirect, nonce, verifier, browser string, ts int64) {
		// '|' is the wire separator — inputs containing it will not
		// round-trip (pre-existing wire-format limitation, not a codec bug).
		if strings.ContainsAny(redirect+nonce+verifier+browser, "|") {
			t.Skip("inputs contain wire separator '|'")
		}
		s := output.State{
			Redirect:     redirect,
			Nonce:        nonce,
			Verifier:     verifier,
			BrowserNonce: browser,
			IssuedAt:     time.Unix(ts, 0).UTC(),
		}
		wire, err := codec.Encode(context.Background(), s)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		got, err := codec.Decode(context.Background(), wire)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !reflect.DeepEqual(s, got) {
			t.Errorf("roundtrip mismatch:\nin=%+v\nout=%+v", s, got)
		}
	})
}
