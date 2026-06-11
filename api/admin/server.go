// Package admin provides the admin API HTTP server.
// It runs on a separate port from the public OAuth server.
package admin

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/observability"
)

// Server is the admin API HTTP server.
type Server struct {
	srv *http.Server
	obs *observability.Provider
}

// OptionalDeps groups optional admin server dependencies.
// All fields are nil-safe — omit any that are not configured.
type OptionalDeps struct {
	System          *SystemDeps
	Keys            *KeysDeps
	DCR             *DCRDeps
	XAA             *XAADeps
	Resources       *ResourceAdminDeps
	BrokerProviders *BrokerProviderAdminDeps
	Grants          *GrantAdminDeps
	Issuances       *IssuanceAdminDeps
	Fronting        *FrontingAdminDeps
}

// NewServer creates the admin HTTP server with routes wired.
// opts fields are all optional (nil if not configured).
func NewServer(ctx context.Context, cfg config.AdminConfig, admin Provider, obs *observability.Provider, opts OptionalDeps) *Server {
	mux := http.NewServeMux()

	s := &Server{
		srv: &http.Server{
			Addr:              cfg.Address,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		},
		obs: obs,
	}

	// Optional rate limiting.
	var inner http.Handler = mux
	if cfg.RequestsPerSecond > 0 && cfg.Burst > 0 {
		inner = newAdminRateLimiter(ctx, cfg.RequestsPerSecond, cfg.Burst).Wrap(mux)
	}

	// Observability middleware chain: Recover → RequestID → Tracing → Metrics → Logging → rate limiter → mux
	obsMW := observability.NewHTTPMiddleware(obs)
	s.srv.Handler = obsMW.Recover()(
		obsMW.RequestID()(
			obsMW.Tracing()(
				obsMW.Metrics()(
					obsMW.Logging()(inner),
				),
			),
		),
	)

	// Prometheus metrics endpoint — on admin port only (not public).
	// Registered before auth middleware so operators can scrape without API key.
	if h := obs.PrometheusHandler(); h != nil {
		mux.Handle("GET /metrics", h)
	}

	// Auth middleware + route registration.
	authMW := newAPIKeyMiddleware(cfg.APIKey)
	registerRoutes(mux, authMW, admin, obs, opts.System, opts.Keys, opts.DCR, opts.XAA, opts.Resources, opts.BrokerProviders, opts.Grants, opts.Issuances, opts.Fronting)

	// UI routes — no auth middleware. The SPA manages its own auth
	// via the /admin/auth/verify endpoint.
	registerUIRoutes(mux)

	return s
}

// Handler returns the server's HTTP handler for testing.
func (s *Server) Handler() http.Handler {
	return s.srv.Handler
}

// Start begins listening.
func (s *Server) Start() error {
	s.obs.Logger.Info("admin server listening", "addr", s.srv.Addr)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", s.srv.Addr)
	if err != nil {
		return err
	}
	return s.srv.Serve(ln)
}

// Shutdown gracefully drains in-flight requests.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// adminRateLimiter provides simple per-IP rate limiting for the admin API.
type adminRateLimiter struct {
	rate    rate.Limit
	burst   int
	mu      sync.Mutex
	clients map[string]*rate.Limiter
}

func newAdminRateLimiter(ctx context.Context, rps float64, burst int) *adminRateLimiter {
	rl := &adminRateLimiter{
		rate:    rate.Limit(rps),
		burst:   burst,
		clients: make(map[string]*rate.Limiter),
	}
	go rl.cleanupLoop(ctx)
	return rl
}

// cleanupLoop periodically removes stale limiter entries to prevent unbounded map growth.
func (rl *adminRateLimiter) cleanupLoop(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			// Silently recover — prevents goroutine crash from taking down the process.
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
			for key := range rl.clients {
				delete(rl.clients, key)
			}
			rl.mu.Unlock()
		}
	}
}

func (rl *adminRateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	l, ok := rl.clients[ip]
	if !ok {
		l = rate.NewLimiter(rl.rate, rl.burst)
		rl.clients[ip] = l
	}
	return l
}

// Wrap applies rate limiting middleware to the given handler.
func (rl *adminRateLimiter) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip == "" {
			ip = r.RemoteAddr
		}
		if !rl.getLimiter(ip).Allow() {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"slow_down","error_description":"rate limit exceeded"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}
