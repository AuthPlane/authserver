package public

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/observability"
)

// The public listener must cap request headers. Without a cap Go accepts
// about 1 MB of headers, and an anonymous caller can put most of that into a
// DPoP proof or bearer token that is parsed as a JWS before any
// authentication. Measured against a real listener because the cap has two
// layers: RequestHeaderLimit in the chain and MaxHeaderBytes on http.Server.
func TestPublicListener_RejectsOversizedHeaders(t *testing.T) {
	addr := startPublicListener(t)

	// Over the cap: RequestHeaderLimit answers inside the chain.
	if got := probeHeaderStatus(t, addr, shared.MaxRequestHeaderBytes+8<<10); got != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("header over the limit: status %d, want %d", got, http.StatusRequestHeaderFieldsTooLarge)
	}
	// Over the server backstop: net/http answers before any handler.
	if got := probeHeaderStatus(t, addr, shared.ServerMaxHeaderBytes+8<<10); got != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("header over the backstop: status %d, want %d", got, http.StatusRequestHeaderFieldsTooLarge)
	}
	// Real traffic still fits: 16 KiB is several times a DPoP proof, an access
	// token and a session cookie together.
	if got := probeHeaderStatus(t, addr, 16<<10); got == http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("16 KiB header: rejected with %d, want it to reach the handler", got)
	}
}

func startPublicListener(t *testing.T) string {
	t.Helper()
	addr := freeLocalAddr(t)
	srv := NewServer(context.Background(), config.ServerConfig{
		Issuer:  "https://auth.example.com",
		Address: addr,
	}, newTestServerDeps(false, nil), observability.NewNoop())
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	waitForListener(t, addr)
	return addr
}

func freeLocalAddr(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		d := net.Dialer{Timeout: 100 * time.Millisecond}
		if c, err := d.DialContext(context.Background(), "tcp", addr); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("listener at %s did not come up", addr)
}

// probeHeaderStatus sends one request whose X-Pad header carries
// headerValueBytes bytes over a raw connection (so no client-side limit
// interferes) and returns the response status.
func probeHeaderStatus(t *testing.T, addr string, headerValueBytes int) int {
	t.Helper()
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	req := fmt.Sprintf("GET /healthz HTTP/1.1\r\nHost: %s\r\nX-Pad: %s\r\nConnection: close\r\n\r\n", addr, strings.Repeat("a", headerValueBytes))
	if _, werr := conn.Write([]byte(req)); werr != nil {
		t.Fatalf("write: %v", werr)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}
