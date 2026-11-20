package shared

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The limit must stay well above real traffic. The sizes are the ones the
// constant's comment is sized against: a DPoP proof with a 4096-bit RSA key
// (~2.3 KB), a large access token, and a session cookie.
func TestMaxRequestHeaderBytes_FitsRealTraffic(t *testing.T) {
	const realisticHeaders = 2400 + 4096 + 1024 + 2048 // DPoP + Authorization + Cookie + the rest
	if MaxRequestHeaderBytes < 2*realisticHeaders {
		t.Fatalf("MaxRequestHeaderBytes = %d, want at least twice a realistic header block (%d)", MaxRequestHeaderBytes, realisticHeaders)
	}
	// And small enough to be a real bound: Go's own default is 1 MB.
	if MaxRequestHeaderBytes > 64<<10 {
		t.Fatalf("MaxRequestHeaderBytes = %d, want at most 64 KiB", MaxRequestHeaderBytes)
	}
}

func TestRequestHeaderLimit(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	reached := false
	h := RequestHeaderLimit(logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	}))

	t.Run("under the limit reaches the handler", func(t *testing.T) {
		reached = false
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
		r.Header.Set("X-Pad", strings.Repeat("a", 16<<10))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if !reached || w.Code != http.StatusNoContent {
			t.Fatalf("reached=%v status=%d, want the handler's 204", reached, w.Code)
		}
		if logs.Len() != 0 {
			t.Fatalf("logged for an allowed request: %s", logs.String())
		}
	})

	t.Run("over the limit gets 431 with a warning", func(t *testing.T) {
		reached = false
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
		secret := strings.Repeat("s", MaxRequestHeaderBytes)
		r.Header.Set("Cookie", "big="+secret)
		r.Header.Set("X-Small", "x")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if reached {
			t.Fatal("handler ran for an oversized request")
		}
		if w.Code != http.StatusRequestHeaderFieldsTooLarge {
			t.Fatalf("status = %d, want 431", w.Code)
		}
		if got := w.Body.String(); got != "431 Request Header Fields Too Large" {
			t.Errorf("body = %q, want net/http's text", got)
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
			t.Errorf("Content-Type = %q, want text/plain", ct)
		}
		out := logs.String()
		if !strings.Contains(out, "request headers too large") || !strings.Contains(out, "Cookie=") || !strings.Contains(out, "limit_bytes=32768") {
			t.Fatalf("warning lacks message, header name or limit: %s", out)
		}
		if strings.Contains(out, "ssssssss") {
			t.Fatal("warning logged a header value")
		}
	})
}

// RequestHeaderBytes must track what net/http counts closely enough that the
// in-chain cap, not the server backstop, decides near the limit.
func TestRequestHeaderBytes_MatchesWireSize(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/a?b=c", nil)
	r.Host = "auth.example.com"
	r.Header.Set("X-One", "1")
	r.Header.Add("X-Two", "22")
	r.Header.Add("X-Two", "333")
	wire := "GET /a?b=c HTTP/1.1\r\nHost: auth.example.com\r\nX-One: 1\r\nX-Two: 22\r\nX-Two: 333\r\n\r\n"
	if got := RequestHeaderBytes(r); got != len(wire) {
		t.Fatalf("RequestHeaderBytes = %d, want %d (the HTTP/1.1 wire size)", got, len(wire))
	}
}

func TestServerMaxHeaderBytes_IsABackstopAboveTheCap(t *testing.T) {
	// Requests the common proxies pass on (up to about 64 KB) must reach the
	// in-chain cap, which reports them, rather than net/http's silent 431.
	if ServerMaxHeaderBytes+4<<10 < 64<<10 {
		t.Fatalf("ServerMaxHeaderBytes = %d, want the backstop above 64 KiB with Go's slack", ServerMaxHeaderBytes)
	}
	if ServerMaxHeaderBytes > 128<<10 {
		t.Fatalf("ServerMaxHeaderBytes = %d, want it to stay a tight bound", ServerMaxHeaderBytes)
	}
}
