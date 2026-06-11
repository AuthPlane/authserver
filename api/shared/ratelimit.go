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

// LockoutCallback is called when a request is blocked by lockout.
type LockoutCallback func(ip string)

// RateLimiter provides per-IP rate limiting and auth failure lockout.
type RateLimiter struct {
	cfg            config.RateLimitConfig
	visitors       map[string]*visitorState
	mu             sync.Mutex
	OnLockoutBlock LockoutCallback
}

type visitorState struct {
	limiter      *rate.Limiter
	failCount    int
	firstFailure time.Time
	lockedUntil  time.Time
}

// NewRateLimiter creates a new rate limiter from the given config.
// The provided context controls the lifetime of the background cleanup goroutine.
func NewRateLimiter(ctx context.Context, cfg config.RateLimitConfig) *RateLimiter {
	rl := &RateLimiter{
		cfg:      cfg,
		visitors: make(map[string]*visitorState),
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
			now := time.Now()
			for key, v := range rl.visitors {
				// Remove visitors whose lockout has expired and have no recent failures.
				if now.After(v.lockedUntil) && v.failCount == 0 {
					delete(rl.visitors, key)
				}
			}
			rl.mu.Unlock()
		}
	}
}

func (rl *RateLimiter) getVisitor(key string) *visitorState {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, ok := rl.visitors[key]
	if !ok {
		v = &visitorState{
			limiter: rate.NewLimiter(rate.Limit(rl.cfg.RequestsPerSecond), rl.cfg.Burst),
		}
		rl.visitors[key] = v
	}
	return v
}

// Middleware wraps an HTTP handler with rate limiting.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r)
		v := rl.getVisitor(ip)

		// Check lockout.
		if rl.IsLockedOut(ip) {
			if rl.OnLockoutBlock != nil {
				rl.OnLockoutBlock(ip)
			}
			w.Header().Set("Retry-After", "60")
			WriteOAuthError(w, http.StatusTooManyRequests, "slow_down", "too many failed attempts, try again later")
			return
		}

		// Check rate limit.
		if !v.limiter.Allow() {
			w.Header().Set("Retry-After", "1")
			WriteOAuthError(w, http.StatusTooManyRequests, "slow_down", "rate limit exceeded")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RecordAuthFailure tracks a failed authentication attempt for the given key.
func (rl *RateLimiter) RecordAuthFailure(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, ok := rl.visitors[key]
	if !ok {
		v = &visitorState{
			limiter: rate.NewLimiter(rate.Limit(rl.cfg.RequestsPerSecond), rl.cfg.Burst),
		}
		rl.visitors[key] = v
	}

	now := time.Now()

	// Reset counter if outside the failure window.
	if v.failCount > 0 && now.Sub(v.firstFailure) > rl.cfg.AuthFailWindow {
		v.failCount = 0
	}

	if v.failCount == 0 {
		v.firstFailure = now
	}
	v.failCount++

	if v.failCount >= rl.cfg.AuthFailMax {
		v.lockedUntil = now.Add(rl.cfg.AuthLockout)
		v.failCount = 0 // reset after lockout
	}
}

// IsLockedOut checks if a key is currently locked out due to too many failures.
func (rl *RateLimiter) IsLockedOut(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, ok := rl.visitors[key]
	if !ok {
		return false
	}

	if time.Now().Before(v.lockedUntil) {
		return true
	}
	return false
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
