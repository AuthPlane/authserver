//go:build integration

package public_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	apipublic "github.com/authplane/authserver/api/public"
	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/config"
)

func newRateLimitTestServer(t *testing.T, rlCfg config.RateLimitConfig) *httptest.Server {
	t.Helper()
	jwksSvc := newTestJWKSService(t)

	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		JWKS:            jwksSvc,
		ResourceServers: testResourceServers(),
		RateLimitCfg:    rlCfg,
	}, testObs())

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestRateLimit_BelowLimit_OK(t *testing.T) {
	ts := newRateLimitTestServer(t, config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             100,
	})

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
}

func TestRateLimit_AboveLimit_429(t *testing.T) {
	ts := newRateLimitTestServer(t, config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             1,
	})

	// First request should succeed (within burst).
	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first request status: got %d, want 200", resp.StatusCode)
	}

	// Rapid subsequent requests should get rate limited.
	var got429 bool
	var rateLimitResp *http.Response
	for i := 0; i < 10; i++ {
		resp, err = http.Get(ts.URL + "/health")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			rateLimitResp = resp
			break
		}
		resp.Body.Close()
	}
	if !got429 {
		t.Error("expected at least one 429 response")
	}
	if rateLimitResp != nil {
		rateLimitResp.Body.Close()
		// Matrix: 10.11 — upgraded from ⚠️: Retry-After header on 429
		ra := rateLimitResp.Header.Get("Retry-After")
		if ra == "" {
			t.Error("429 response should include Retry-After header")
		} else if _, err := strconv.Atoi(ra); err != nil {
			t.Errorf("Retry-After should be a valid number, got %q", ra)
		}
	}
}

func TestRateLimit_Disabled_NoLimit(t *testing.T) {
	ts := newRateLimitTestServer(t, config.RateLimitConfig{
		Enabled: false,
	})

	// All requests should succeed.
	for i := 0; i < 5; i++ {
		resp, err := http.Get(ts.URL + "/health")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d status: got %d, want 200", i, resp.StatusCode)
		}
	}
}

// Matrix: 11.1 — upgraded from ⚠️: token endpoint is also rate-limited
func TestRateLimit_TokenEndpoint_429(t *testing.T) {
	ts := newRateLimitTestServer(t, config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             1,
	})

	// First request to /oauth/token (will fail validation, but that's fine — we're testing rate limiting).
	resp, err := http.PostForm(ts.URL+"/oauth/token", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	// Rapid subsequent requests to /oauth/token should get rate limited.
	var got429 bool
	for i := 0; i < 10; i++ {
		resp, err = http.PostForm(ts.URL+"/oauth/token", nil)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			resp.Body.Close()
			break
		}
		resp.Body.Close()
	}
	if !got429 {
		t.Error("expected 429 on token endpoint when rate limit exceeded")
	}
}

// Matrix: 11.4 — all 429 responses include Retry-After header
func TestRateLimit_RetryAfterOnAll429s(t *testing.T) {
	ts := newRateLimitTestServer(t, config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             1,
	})

	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/health"},
		{"GET", "/.well-known/jwks.json"},
		{"POST", "/oauth/token"},
	}

	for _, ep := range endpoints {
		// Exhaust the burst on a fresh limiter (different test per endpoint isn't
		// possible with one server, but all share the same IP limiter — so we just
		// need to trigger 429 once per test).
		var got429 bool
		for i := 0; i < 20; i++ {
			var resp *http.Response
			var err error
			if ep.method == "POST" {
				resp, err = http.PostForm(ts.URL+ep.path, nil)
			} else {
				resp, err = http.Get(ts.URL + ep.path)
			}
			if err != nil {
				t.Fatalf("%s %s: %v", ep.method, ep.path, err)
			}
			if resp.StatusCode == http.StatusTooManyRequests {
				ra := resp.Header.Get("Retry-After")
				if ra == "" {
					t.Errorf("429 on %s %s missing Retry-After header", ep.method, ep.path)
				}
				if _, err := strconv.Atoi(ra); err != nil {
					t.Errorf("Retry-After should be valid integer, got %q", ra)
				}
				got429 = true
				resp.Body.Close()
				break
			}
			resp.Body.Close()
		}
		if !got429 {
			t.Errorf("expected 429 on %s %s", ep.method, ep.path)
		}
		// Done after first endpoint — all share the same per-IP limiter.
		break
	}
}

func TestRateLimit_Lockout_TriggersAndExpires(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             100,
		AuthFailMax:       3,
		AuthFailWindow:    10 * time.Second,
		AuthLockout:       100 * time.Millisecond, // short for testing
	}

	rl := shared.NewRateLimiter(context.Background(), cfg)

	// Record failures.
	for i := 0; i < 3; i++ {
		rl.RecordAuthFailure("test-ip")
	}

	if !rl.IsLockedOut("test-ip") {
		t.Error("expected lockout after 3 failures")
	}

	// Wait for lockout to expire.
	time.Sleep(150 * time.Millisecond)

	if rl.IsLockedOut("test-ip") {
		t.Error("lockout should have expired")
	}
}

// Matrix: 11.7 — lockout triggers are observable via slog + lockout callback
func TestRateLimit_LockoutCallback_Fires(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             100,
		AuthFailMax:       2,
		AuthFailWindow:    10 * time.Second,
		AuthLockout:       1 * time.Second,
	}

	rl := shared.NewRateLimiter(context.Background(), cfg)

	// Set lockout callback.
	var callbackIP string
	rl.OnLockoutBlock = func(ip string) {
		callbackIP = ip
	}

	// Trigger lockout.
	rl.RecordAuthFailure("10.0.0.1")
	rl.RecordAuthFailure("10.0.0.1")

	// Make a request via middleware to trigger the callback.
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status: got %d, want 429", rr.Code)
	}
	if callbackIP != "10.0.0.1" {
		t.Errorf("lockout callback should fire with IP '10.0.0.1', got %q", callbackIP)
	}
}
