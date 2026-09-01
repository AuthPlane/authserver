package shared

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/authplane/authserver/internal/config"
)

// RateLimiter provides per-IP request throughput limiting.
//
// It deliberately does NOT handle auth-failure lockout — see AuthLockout.
// Throughput is a property of the connection and applies to every public
// endpoint; a lockout is a property of an account and belongs on the
// authentication route only. Conflating them is what let ten failed logins
// return 429 from JWKS.
type RateLimiter struct {
	cfg      config.RateLimitConfig
	visitors map[string]*rate.Limiter
	mu       sync.Mutex
}

// NewRateLimiter creates a new rate limiter from the given config.
// The provided context controls the lifetime of the background cleanup goroutine.
func NewRateLimiter(ctx context.Context, cfg config.RateLimitConfig) *RateLimiter {
	rl := &RateLimiter{
		cfg:      cfg,
		visitors: make(map[string]*rate.Limiter),
	}
	// Background cleanup of stale visitor entries every 5 minutes.
	go rl.cleanupLoop(ctx)
	return rl
}

// cleanupLoop periodically removes stale visitor entries to prevent unbounded memory growth.
func (rl *RateLimiter) cleanupLoop(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			// Silently recover — no logger available in rate limiter.
			_ = r
		}
	}()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.mu.Lock()
			for key, v := range rl.visitors {
				// A limiter back at full burst is equivalent to a fresh one.
				if v.Tokens() >= float64(rl.cfg.Burst) {
					delete(rl.visitors, key)
				}
			}
			rl.mu.Unlock()
		}
	}
}

func (rl *RateLimiter) getVisitor(key string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, ok := rl.visitors[key]
	if !ok {
		v = rate.NewLimiter(rate.Limit(rl.cfg.RequestsPerSecond), rl.cfg.Burst)
		rl.visitors[key] = v
	}
	return v
}

// Middleware wraps an HTTP handler with rate limiting.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.getVisitor(ClientIP(r)).Allow() {
			w.Header().Set("Retry-After", "1")
			WriteOAuthError(w, http.StatusTooManyRequests, "slow_down", "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ClientIP extracts the client IP from the request.
// Uses RemoteAddr only -- X-Forwarded-For is ignored to prevent spoofing.
func ClientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
