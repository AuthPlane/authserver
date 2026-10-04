package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIPContext_RoundTrip(t *testing.T) {
	if ip, ok := ClientIPFromContext(context.Background()); ok || ip != "" {
		t.Fatalf("empty ctx: got (%q, %v), want (\"\", false)", ip, ok)
	}

	ctx := WithClientIP(context.Background(), "203.0.113.7")
	ip, ok := ClientIPFromContext(ctx)
	if !ok || ip != "203.0.113.7" {
		t.Fatalf("got (%q, %v), want (203.0.113.7, true)", ip, ok)
	}

	if ip, ok := ClientIPFromContext(WithClientIP(context.Background(), "")); ok || ip != "" {
		t.Fatalf("blank ip should read as absent, got (%q, %v)", ip, ok)
	}
}

func TestRemoteIP(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7:51234": "203.0.113.7",
		"[2001:db8::1]:443": "2001:db8::1",
		"203.0.113.7":       "203.0.113.7",
		"":                  "",
	}
	for addr, want := range cases {
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
		r.RemoteAddr = addr
		if got := RemoteIP(r); got != want {
			t.Errorf("RemoteIP(%q) = %q, want %q", addr, got, want)
		}
	}
}

func TestRequestID_SetsClientIPOnContext(t *testing.T) {
	mw := NewHTTPMiddleware(NewNoop())

	var gotIP string
	var gotOK bool
	handler := mw.RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIP, gotOK = ClientIPFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	req.RemoteAddr = "198.51.100.23:40000"
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if !gotOK || gotIP != "198.51.100.23" {
		t.Fatalf("handler saw client ip (%q, %v), want (198.51.100.23, true)", gotIP, gotOK)
	}
}
