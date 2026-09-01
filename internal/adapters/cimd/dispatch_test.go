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
// safe or plain transport from the per-request context value — and crucially
// fails closed to the safe transport when the context carries no policy (the
// branch Fetch never exercises because it always stamps the value).
func TestDispatchTransport_RoutesByContext(t *testing.T) {
	var hit string
	d := &dispatchTransport{
		safe:  recordingRT{name: "safe", hit: &hit},
		plain: recordingRT{name: "plain", hit: &hit},
	}

	tests := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{"bare context fails closed to safe", context.Background(), "safe"},
		{"RequireHTTPS=true routes to safe", withRequireHTTPS(context.Background(), true), "safe"},
		{"RequireHTTPS=false routes to plain", withRequireHTTPS(context.Background(), false), "plain"},
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
