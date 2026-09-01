// internal/ports/output/state_codec_example_test.go
package output_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/authplane/authserver/internal/ports/output"
)

// requestIDCodec is an illustrative non-default StateCodec impl that
// serializes Extra into the wire format (here, naively as JSON). The
// motivating use-case is distributed-tracing correlation: a deployment
// that wants to thread a request_id through the OIDC flow can do so
// by populating state.Extra["request_id"] at Encode time and reading
// it back at Decode time.
//
// NOT used in production. Demonstrates that the port shape supports
// Extra-bearing implementations without OSS needing to know about them.
type requestIDCodec struct{}

func (c *requestIDCodec) Encode(_ context.Context, s output.State) ([]byte, error) {
	return json.Marshal(s)
}

func (c *requestIDCodec) Decode(_ context.Context, b []byte) (output.State, error) {
	var s output.State
	if err := json.Unmarshal(b, &s); err != nil {
		return output.State{}, fmt.Errorf("requestIDCodec decode: %w", err)
	}
	return s, nil
}

func TestStateCodec_Substitute_RoundTripsExtra(t *testing.T) {
	var c output.StateCodec = &requestIDCodec{}
	in := output.State{
		Redirect:     "/dashboard",
		Nonce:        "n",
		Verifier:     "v",
		BrowserNonce: "b",
		Extra:        map[string]string{"request_id": "abc-123"},
	}

	wire, err := c.Encode(context.Background(), in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, err := c.Decode(context.Background(), wire)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := out.Extra["request_id"]; got != "abc-123" {
		t.Errorf("Extra[request_id]=%q, want %q", got, "abc-123")
	}
	if out.Redirect != in.Redirect || out.Nonce != in.Nonce {
		t.Errorf("base fields did not roundtrip: %+v", out)
	}
}
