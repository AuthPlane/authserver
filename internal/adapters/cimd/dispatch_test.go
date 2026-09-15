package cimd

import (
	"context"
	"net/http"
	"testing"
)

// recordingRT records which transport was selected and returns a minimal response.
type recordingRT struct {
	name string
	hit  *string
}

func (r recordingRT) RoundTrip(_ *http.Request) (*http.Response, error) {
	*r.hit = r.name
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
}

// TestDispatchTransport_RoutesByContext verifies dispatchTransport routes to the
// filtering or non-filtering transport from the per-request context value — and
// crucially fails closed to the filtering one when the context carries no policy
// (the branch Fetch never exercises because it always stamps the value).
func TestDispatchTransport_RoutesByContext(t *testing.T) {
	var hit string
	d := &dispatchTransport{
		strict:     recordingRT{name: "strict", hit: &hit},
		permissive: recordingRT{name: "permissive", hit: &hit},
	}

	tests := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{"bare context fails closed to strict", context.Background(), "strict"},
		{"AllowPrivate=false routes to strict", withAllowPrivate(context.Background(), false), "strict"},
		{"AllowPrivate=true routes to permissive", withAllowPrivate(context.Background(), true), "permissive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hit = ""
			req, err := http.NewRequestWithContext(tt.ctx, http.MethodGet, "https://example.com", http.NoBody)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			resp, err := d.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			_ = resp.Body.Close()
			if hit != tt.want {
				t.Errorf("routed to %q, want %q", hit, tt.want)
			}
		})
	}
}

// The scheme of the request must not influence transport selection: that is the
// coupling this change removes, and nothing but the address policy may decide.
func TestDispatchTransport_IgnoresScheme(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			var hit string
			d := &dispatchTransport{
				strict:     recordingRT{name: "strict", hit: &hit},
				permissive: recordingRT{name: "permissive", hit: &hit},
			}
			req, err := http.NewRequestWithContext(
				withAllowPrivate(context.Background(), false),
				http.MethodGet, scheme+"://example.com", http.NoBody)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			resp, err := d.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			_ = resp.Body.Close()
			if hit != "strict" {
				t.Errorf("scheme %s routed to %q, want strict", scheme, hit)
			}
		})
	}
}
